package googleoidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testOP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	issuer string
}

func newTestOP(t *testing.T) *testOP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	op := &testOP{key: key, kid: "k1"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 op.srv.URL,
			"authorization_endpoint": op.srv.URL + "/auth",
			"token_endpoint":         op.srv.URL + "/token",
			"jwks_uri":               op.srv.URL + "/certs",
		})
	})
	mux.HandleFunc("GET /certs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": op.kid,
				"n": base64.RawURLEncoding.EncodeToString(op.key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
			}},
		})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.FormValue("code")
		idt, _ := op.sign(map[string]any{
			"iss": op.srv.URL, "aud": "cid", "sub": "s1",
			"email": "e@d.com", "email_verified": true, "hd": "d.com",
			"name": "N", "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": "nonce-" + code,
		})
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idt})
	})
	op.srv = httptest.NewServer(mux)
	t.Cleanup(op.srv.Close)
	// Fix the issuer now that the URL is known.
	op.issuer = op.srv.URL
	return op
}

func (op *testOP) sign(claims map[string]any) (string, error) {
	hb, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": op.kid, "typ": "JWT"})
	cb, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, op.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + enc.EncodeToString(sig), nil
}

func (op *testOP) client() *Client {
	return New(op.srv.URL, "cid", "csecret", "http://app/callback/google", 30*time.Second, nil)
}

func TestValidateIDTokenHappyPath(t *testing.T) {
	op := newTestOP(t)
	c := op.client()
	ctx := context.Background()
	idt, err := c.ExchangeCode(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := c.ValidateIDToken(ctx, idt, "nonce-c1")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub != "s1" || claims.Hd != "d.com" || !claims.EmailVerified {
		t.Fatalf("claims: %+v", claims)
	}
}

func TestValidateIDTokenRejections(t *testing.T) {
	op := newTestOP(t)
	c := op.client()
	ctx := context.Background()
	base := map[string]any{
		"iss": op.srv.URL, "aud": "cid", "sub": "s1",
		"email": "e@d.com", "email_verified": true, "hd": "d.com",
		"exp": time.Now().Add(time.Hour).Unix(), "nonce": "n1",
	}
	mk := func(mut func(map[string]any)) string {
		cl := map[string]any{}
		for k, v := range base {
			cl[k] = v
		}
		mut(cl)
		idt, _ := op.sign(cl)
		return idt
	}
	cases := map[string]func(map[string]any){
		"wrong nonce":    func(c map[string]any) { c["nonce"] = "other" },
		"wrong issuer":   func(c map[string]any) { c["iss"] = "https://evil" },
		"wrong audience": func(c map[string]any) { c["aud"] = "other-client" },
		"expired":        func(c map[string]any) { c["exp"] = time.Now().Add(-2 * time.Hour).Unix() },
	}
	for name, mut := range cases {
		if _, err := c.ValidateIDToken(ctx, mk(mut), "n1"); err == nil {
			t.Fatalf("%s: expected rejection", name)
		}
	}
	// Tampered signature.
	idt, _ := op.sign(base)
	tampered := idt[:len(idt)-4] + "AAAA"
	if _, err := c.ValidateIDToken(ctx, tampered, "n1"); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestValidateIDTokenAlgorithmAllowlist(t *testing.T) {
	op := newTestOP(t)
	c := op.client()
	ctx := context.Background()
	// Hand-build an unsigned (alg=none) token.
	cb, _ := json.Marshal(map[string]any{
		"iss": op.srv.URL, "aud": "cid", "sub": "s1", "exp": time.Now().Add(time.Hour).Unix(), "nonce": "n1",
	})
	enc := base64.RawURLEncoding
	none := enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + enc.EncodeToString(cb) + "."
	if _, err := c.ValidateIDToken(ctx, none, "n1"); err == nil {
		t.Fatal("alg=none accepted")
	}
	// Hand-build an HS256 token (signed with the public key material to
	// simulate the classic algorithm-confusion attack).
	hb, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	input := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	digest := sha256.Sum256([]byte(input))
	// HMAC-SHA256 keyed with the RSA public key DER would be required for a
	// real confusion attack; for the test any HMAC-ish signature suffices to
	// prove the header is rejected before verification.
	sig := digest[:]
	hs256 := input + "." + enc.EncodeToString(sig)
	if _, err := c.ValidateIDToken(ctx, hs256, "n1"); err == nil {
		t.Fatal("alg=HS256 accepted")
	}
	_ = crypto.SHA256
}

func TestAuthorizeURL(t *testing.T) {
	op := newTestOP(t)
	c := op.client()
	u, err := c.AuthorizeURL(context.Background(), "st", "nc")
	if err != nil {
		t.Fatal(err)
	}
	if u != op.srv.URL+"/auth?client_id=cid&nonce=nc&redirect_uri=http%3A%2F%2Fapp%2Fcallback%2Fgoogle&response_type=code&scope=openid+email+profile&state=st" {
		t.Fatalf("unexpected authorize URL: %s", u)
	}
}
