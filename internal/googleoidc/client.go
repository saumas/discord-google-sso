// Package googleoidc implements the Google OIDC client: discovery,
// authorization redirect, code exchange, JWKS fetch, and ID-token
// validation with an explicit JWS algorithm allowlist (RS256 only).
package googleoidc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DiscoveryDoc is the subset of the OIDC discovery document we use.
type DiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Claims is the validated ID-token claim set relevant to policy.
type Claims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Hd            string `json:"hd"`
	Name          string `json:"name"`
}

// Client is a Google OIDC client against the configured base URL.
type Client struct {
	baseURL      string
	clientID     string
	clientSecret string
	callbackURL  string
	leeway       time.Duration
	hc           *http.Client
	log          *slog.Logger

	mu          sync.Mutex
	discovery   *DiscoveryDoc
	jwks        map[string]crypto.PublicKey
	jwksFetched time.Time
}

// New returns a Client.
func New(baseURL, clientID, clientSecret, callbackURL string, leeway time.Duration, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURL:  callbackURL,
		leeway:       leeway,
		hc:           &http.Client{Timeout: 15 * time.Second},
		log:          log,
	}
}

// Discovery fetches (and caches) the OIDC discovery document.
func (c *Client) Discovery(ctx context.Context) (*DiscoveryDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.discovery != nil {
		return c.discovery, nil
	}
	var d DiscoveryDoc
	if err := c.getJSON(ctx, c.baseURL+"/.well-known/openid-configuration", &d, noLogBody); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if d.Issuer == "" || d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return nil, errors.New("oidc discovery document is missing required endpoints")
	}
	c.discovery = &d
	return c.discovery, nil
}

// AuthorizeURL builds the Google authorization redirect.
func (c *Client) AuthorizeURL(ctx context.Context, state, nonce string) (string, error) {
	d, err := c.Discovery(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"client_id":     {c.clientID},
		"redirect_uri":  {c.callbackURL},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"nonce":         {nonce},
	}
	return d.AuthorizationEndpoint + "?" + q.Encode(), nil
}

type tokenResp struct {
	IDToken string `json:"id_token"`
}

// ExchangeCode exchanges an authorization code for tokens and returns the
// raw ID token.
func (c *Client) ExchangeCode(ctx context.Context, code string) (string, error) {
	d, err := c.Discovery(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.callbackURL},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc token exchange: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// Bodies of token endpoints are never surfaced (they contain tokens).
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc token exchange failed: status %d", resp.StatusCode)
	}
	var tr tokenResp
	if err := json.Unmarshal(body, &tr); err != nil || tr.IDToken == "" {
		return "", errors.New("oidc token exchange: no id_token in response")
	}
	return tr.IDToken, nil
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (c *Client) fetchJWKS(ctx context.Context, d *DiscoveryDoc) (map[string]crypto.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", d.JWKSURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks fetch: status %d", resp.StatusCode)
	}
	var doc jwksDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jwks parse: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		nb, err1 := base64URLDecode(k.N)
		eb, err2 := base64URLDecode(k.E)
		if err1 != nil || err2 != nil || len(eb) < 1 || len(eb) > 4 {
			continue
		}
		var exp int
		for _, b := range eb {
			exp = exp<<8 | int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: exp}
	}
	return keys, nil
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ValidateIDToken validates the ID token: JWS signature with an explicit
// RS256-only algorithm allowlist, issuer, audience, expiry (with bounded
// clock leeway), and nonce. It returns the relevant claims.
func (c *Client) ValidateIDToken(ctx context.Context, idToken, wantNonce string) (*Claims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("id token: malformed JWT")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	hb, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, errors.New("id token: malformed header")
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, errors.New("id token: malformed header")
	}
	// Explicit algorithm allowlist: only Google's documented RS256.
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("id token: algorithm %q not allowed (RS256 only)", hdr.Alg)
	}

	d, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}

	key, err := c.key(ctx, d, hdr.Kid)
	if err != nil {
		return nil, err
	}

	sig, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, errors.New("id token: malformed signature")
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("id token: JWKS key is not RSA")
	}
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], sig); err != nil {
		return nil, errors.New("id token: signature verification failed")
	}

	pb, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, errors.New("id token: malformed payload")
	}
	var payload struct {
		Claims
		Iss   string `json:"iss"`
		Aud   string `json:"aud"`
		Exp   int64  `json:"exp"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, errors.New("id token: malformed payload")
	}
	if payload.Iss != d.Issuer {
		return nil, fmt.Errorf("id token: issuer mismatch")
	}
	if payload.Aud != c.clientID {
		return nil, errors.New("id token: audience mismatch")
	}
	now := time.Now()
	if time.Unix(payload.Exp, 0).Before(now.Add(-c.leeway)) {
		return nil, errors.New("id token: expired")
	}
	if payload.Nonce != wantNonce {
		return nil, errors.New("id token: nonce mismatch")
	}
	if payload.Sub == "" {
		return nil, errors.New("id token: missing subject")
	}
	out := payload.Claims
	return &out, nil
}

func (c *Client) key(ctx context.Context, d *DiscoveryDoc, kid string) (crypto.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jwks != nil {
		if k, ok := c.jwks[kid]; ok {
			return k, nil
		}
		if time.Since(c.jwksFetched) < time.Minute {
			// Recently fetched and the kid is absent: unknown key.
			return nil, fmt.Errorf("id token: unknown key id %q", kid)
		}
	}
	keys, err := c.fetchJWKS(ctx, d)
	if err != nil {
		return nil, err
	}
	c.jwks = keys
	c.jwksFetched = time.Now()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("id token: unknown key id %q", kid)
}

type bodyPolicy int

const (
	logBody bodyPolicy = iota
	noLogBody
)

func (c *Client) getJSON(ctx context.Context, url string, out any, _ bodyPolicy) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
