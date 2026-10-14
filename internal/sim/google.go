package sim

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// GoogleSim is the Google OIDC provider simulator: discovery, authorization,
// token, and JWKS endpoints, with RS256-signed ID tokens.
type GoogleSim struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string

	key *rsa.PrivateKey
	kid string

	mu sync.Mutex
	// the simulated logged-in Google identity
	login googleIdentity
	// auth codes -> codeInfo
	codes map[string]codeInfo
	// issued id tokens / codes (for log redaction assertions)
	issuedSecrets []string
	// mangleNonce corrupts the nonce in issued ID tokens (abuse test).
	mangleNonce bool

	failures failureEngine
	log      *slog.Logger
}

type googleIdentity struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	Name          string `json:"name"`
	Hd            string `json:"hd"`
	EmailVerified bool   `json:"email_verified"`
}

type codeInfo struct {
	nonce string
}

// NewGoogleSim constructs the simulator, generating a fresh RSA signing key.
func NewGoogleSim(issuer, clientID, clientSecret, redirectURI string, log *slog.Logger) (*GoogleSim, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &GoogleSim{
		Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret, RedirectURI: redirectURI,
		key:   key,
		kid:   "sim-key-1",
		codes: map[string]codeInfo{},
		log:   log,
	}, nil
}

// Handler returns the HTTP handler.
func (g *GoogleSim) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", g.handleDiscovery)
	mux.HandleFunc("GET /o/oauth2/v2/auth", g.handleAuthorize)
	mux.HandleFunc("POST /o/oauth2/v2/auth/decision", g.handleAuthorizeDecision)
	mux.HandleFunc("POST /token", g.handleToken)
	mux.HandleFunc("GET /oauth2/v3/certs", g.handleCerts)
	mux.HandleFunc("POST /_admin/reset", g.adminReset)
	mux.HandleFunc("POST /_admin/login-as", g.adminLoginAs)
	mux.HandleFunc("POST /_admin/fail", g.adminFail)
	mux.HandleFunc("POST /_admin/clear-failures", func(w http.ResponseWriter, _ *http.Request) {
		g.failures.clear()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /_admin/mangle-nonce", g.adminMangleNonce)
	mux.HandleFunc("GET /_admin/dump", g.adminDump)
	return mux
}

func (g *GoogleSim) gate(w http.ResponseWriter, r *http.Request) bool {
	if blocked, status, delay := g.failures.check(r.URL.Path); blocked {
		if delay > 0 {
			time.Sleep(delay)
		}
		w.WriteHeader(status)
		return false
	}
	return true
}

func (g *GoogleSim) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{
		"issuer":                 g.Issuer,
		"authorization_endpoint": g.Issuer + "/o/oauth2/v2/auth",
		"token_endpoint":         g.Issuer + "/token",
		"jwks_uri":               g.Issuer + "/oauth2/v3/certs",
	})
}

var googleConsent = template.Must(template.New("gconsent").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in with Google</title></head>
<body><h1>Choose an account</h1>
<p>Signed in as <code>{{.User}}</code></p>
<form method="POST" action="{{.Action}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="nonce" value="{{.Nonce}}">
<button id="approve" type="submit" name="decision" value="approve">Continue</button>
<button id="deny" type="submit" name="decision" value="deny">Cancel</button>
</form></body></html>`))

func (g *GoogleSim) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if !g.gate(w, r) {
		return
	}
	q := r.URL.Query()
	if q.Get("client_id") != g.ClientID || q.Get("redirect_uri") != g.RedirectURI {
		http.Error(w, "invalid client", http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	login := g.login
	g.mu.Unlock()
	if login.Sub == "" {
		http.Error(w, "no simulated login", http.StatusUnauthorized)
		return
	}
	_ = googleConsent.Execute(w, consentData{Provider: "Google", User: login.Email, State: q.Get("state"), Action: "/o/oauth2/v2/auth/decision", Nonce: q.Get("nonce")})
}

func (g *GoogleSim) handleAuthorizeDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	q := url.Values{}
	if state := r.FormValue("state"); state != "" {
		q.Set("state", state)
	}
	if r.FormValue("decision") != "approve" {
		q.Set("error", "access_denied")
	} else {
		code := newToken()
		g.mu.Lock()
		g.codes[code] = codeInfo{nonce: r.FormValue("nonce")}
		g.mu.Unlock()
		q.Set("code", code)
	}
	http.Redirect(w, r, g.RedirectURI+"?"+q.Encode(), http.StatusFound)
}

func (g *GoogleSim) handleToken(w http.ResponseWriter, r *http.Request) {
	if !g.gate(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.FormValue("client_id") != g.ClientID ||
		r.FormValue("client_secret") != g.ClientSecret ||
		r.FormValue("grant_type") != "authorization_code" ||
		r.FormValue("redirect_uri") != g.RedirectURI {
		http.Error(w, `{"error": "invalid_client"}`, http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	g.mu.Lock()
	info, ok := g.codes[code]
	login := g.login
	mangle := g.mangleNonce
	g.mu.Unlock()
	if !ok {
		http.Error(w, `{"error": "invalid_grant"}`, http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	delete(g.codes, code)
	g.mu.Unlock()

	now := time.Now()
	claims := map[string]any{
		"iss":            g.Issuer,
		"aud":            g.ClientID,
		"sub":            login.Sub,
		"email":          login.Email,
		"email_verified": login.EmailVerified,
		"name":           login.Name,
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"nonce":          info.nonce,
	}
	if login.Hd != "" {
		claims["hd"] = login.Hd
	}
	if mangle {
		claims["nonce"] = "corrupted-" + info.nonce
	}
	idToken, err := g.sign(claims)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	g.mu.Lock()
	g.issuedSecrets = append(g.issuedSecrets, idToken, code)
	g.mu.Unlock()
	writeJSON(w, map[string]any{"access_token": newToken(), "id_token": idToken, "token_type": "Bearer"})
}

func (g *GoogleSim) sign(claims map[string]any) (string, error) {
	header := map[string]string{"alg": "RS256", "kid": g.kid, "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

func (g *GoogleSim) handleCerts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": g.kid,
			"n":   base64.RawURLEncoding.EncodeToString(g.key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(g.key.E)).Bytes()),
		}},
	})
}

// --- admin ---

func (g *GoogleSim) adminReset(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.login = googleIdentity{}
	g.codes = map[string]codeInfo{}
	g.issuedSecrets = nil
	g.mangleNonce = false
	g.mu.Unlock()
	g.failures.reset()
	w.WriteHeader(http.StatusNoContent)
}

func (g *GoogleSim) adminLoginAs(w http.ResponseWriter, r *http.Request) {
	var id googleIdentity
	if err := json.NewDecoder(r.Body).Decode(&id); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	g.login = id
	g.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (g *GoogleSim) adminFail(w http.ResponseWriter, r *http.Request) {
	var f Failure
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	g.failures.add(f)
	w.WriteHeader(http.StatusNoContent)
}

func (g *GoogleSim) adminMangleNonce(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	g.mu.Lock()
	g.mangleNonce = req.Enabled
	g.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// DumpIssuedSecrets returns every OAuth code, token, and ID token the
// simulator has issued (for log-redaction assertions).
func (g *GoogleSim) DumpIssuedSecrets() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.issuedSecrets...)
}

// GoogleDump is the simulator observable state.
type GoogleDump struct {
	Login         googleIdentity `json:"login"`
	IssuedSecrets []string       `json:"issued_secrets"`
	MangleNonce   bool           `json:"mangle_nonce"`
}

func (g *GoogleSim) adminDump(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	writeJSON(w, GoogleDump{Login: g.login, IssuedSecrets: g.issuedSecrets, MangleNonce: g.mangleNonce})
}
