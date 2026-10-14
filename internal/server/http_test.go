package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/saumas/discord-google-sso/internal/config"
	"github.com/saumas/discord-google-sso/internal/core"
	"github.com/saumas/discord-google-sso/internal/discordapi"
	"github.com/saumas/discord-google-sso/internal/fakeapi"
	"github.com/saumas/discord-google-sso/internal/googleoidc"
	"github.com/saumas/discord-google-sso/internal/session"
	"github.com/saumas/discord-google-sso/internal/sim"
	"github.com/saumas/discord-google-sso/internal/state"
)

type testEnv struct {
	app      *httptest.Server
	discordS *sim.DiscordSim
	googleS  *sim.GoogleSim
	discordH *httptest.Server
	googleH  *httptest.Server
	logBuf   *bytes.Buffer
	core     *core.Service
	store    *state.Store
	client   *http.Client
	guild    string
}

// noRedirect client returns responses without following redirects.
func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	guild := "9001"

	logBuf := &bytes.Buffer{}
	log := slog.New(slog.NewJSONHandler(logBuf, nil))

	// Reserve the app's address first so provider redirects can target it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	appURL := "http://" + ln.Addr().String()
	discordRedirect := appURL + "/callback/discord"
	googleRedirect := appURL + "/callback/google"

	discordS := sim.NewDiscordSim("dclid", "dsecret", discordRedirect, "bottok", log)
	discordH := httptest.NewServer(discordS.Handler())
	t.Cleanup(discordH.Close)

	googleS, err := sim.NewGoogleSim("", "gclid", "gsecret", googleRedirect, log)
	if err != nil {
		t.Fatal(err)
	}
	googleH := httptest.NewServer(googleS.Handler())
	t.Cleanup(googleH.Close)
	googleS.Issuer = googleH.URL

	api := fakeapi.New()
	t.Cleanup(api.Close)
	store := state.NewStore(api.Client(), "ns", "st", log)

	cfg := &config.Config{}
	cfg.GuildID = guild
	cfg.PublicBaseURL = appURL
	cfg.Google.AllowedDomains = []string{"example.com"}
	cfg.AddRoles = []string{"111"}
	cfg.RemoveRoles = []string{"999"}
	cfg.UnverifiedRoles = []string{"888"}
	cfg.AdminRoleIDs = []string{"555"}
	cfg.SessionTTL = time.Minute
	cfg.ClockLeeway = 30 * time.Second
	cfg.Discord.PublicKey = strings.Repeat("ab", 32)

	discordClient := discordapi.New(discordH.URL, "bottok", "dclid", "dsecret", discordRedirect, log)
	googleClient := googleoidc.New(googleH.URL, "gclid", "gsecret", googleRedirect, cfg.ClockLeeway, log)
	sessions := session.NewManager(cfg.SessionTTL)
	svc := core.New(cfg, store, discordClient, sessions, log)

	srv := New(cfg, svc, discordClient, googleClient, sessions, log)
	app := httptest.NewUnstartedServer(srv.Handler())
	app.Listener = ln
	app.Start()
	t.Cleanup(app.Close)

	return &testEnv{
		app: app, discordS: discordS, googleS: googleS, discordH: discordH, googleH: googleH,
		logBuf: logBuf, core: svc, store: store, client: noRedirect(), guild: guild,
	}
}

// loginAsDiscord simulates the browser being logged in as the given user.
func (e *testEnv) loginDiscord(t *testing.T, userID string) {
	t.Helper()
	post(t, e.client, e.discordH.URL+"/_admin/login-as", map[string]string{"user_id": userID})
}

func (e *testEnv) loginGoogle(t *testing.T, id map[string]any) {
	t.Helper()
	post(t, e.client, e.googleH.URL+"/_admin/login-as", id)
}

func (e *testEnv) member(t *testing.T, userID string, roles []string) {
	t.Helper()
	post(t, e.client, e.discordH.URL+"/_admin/member", map[string]any{
		"user_id": userID, "guild_id": e.guild, "roles": roles,
	})
}

func post(t *testing.T, c *http.Client, u string, body any) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Post(u, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

// driveFlow walks the browser flow: app start -> Discord consent -> app
// Discord callback -> Google consent -> app Google callback. approve/approve2
// select Approve or Deny on each consent page.
func (e *testEnv) driveFlow(t *testing.T, discordApprove, googleApprove bool) (finalStatus int, finalBody string) {
	t.Helper()
	c := noRedirect()
	// 1. Start.
	resp := get(t, c, e.app.URL+"/verify")
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, e.discordH.URL+"/oauth2/authorize") {
		t.Fatalf("expected Discord authorize redirect, got %s", loc)
	}
	// 2. Consent page.
	page := getBody(t, c, loc)
	if !strings.Contains(page, "Approve") {
		t.Fatalf("not a consent page: %s", page)
	}
	decision := "approve"
	if !discordApprove {
		decision = "deny"
	}
	resp = submitForm(t, c, loc, page, decision)
	loc = resp.Header.Get("Location")
	if !strings.HasPrefix(loc, e.app.URL+"/callback/discord") {
		t.Fatalf("expected app callback redirect, got %s", loc)
	}
	// 3. App Discord callback -> Google authorize redirect (or a rejection
	// page if the caller is not a member).
	resp = get(t, c, loc)
	loc = resp.Header.Get("Location")
	if discordApprove && loc == "" {
		return resp.StatusCode, getBodyString(t, resp)
	}
	if discordApprove && !strings.HasPrefix(loc, e.googleH.URL+"/o/oauth2/v2/auth") {
		t.Fatalf("expected Google authorize redirect, got %s (status %d)", loc, resp.StatusCode)
	}
	if !discordApprove {
		return resp.StatusCode, getBodyString(t, resp)
	}
	// 4. Google consent.
	page = getBody(t, c, loc)
	decision = "approve"
	if !googleApprove {
		decision = "deny"
	}
	resp = submitForm(t, c, loc, page, decision)
	loc = resp.Header.Get("Location")
	if !strings.HasPrefix(loc, e.app.URL+"/callback/google") {
		t.Fatalf("expected app google callback, got %s", loc)
	}
	// 5. Final page.
	resp = get(t, c, loc)
	return resp.StatusCode, getBodyString(t, resp)
}

func get(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func getBody(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	return getBodyString(t, get(t, c, u))
}

func getBodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// submitForm finds the form in the page and posts the decision.
func submitForm(t *testing.T, c *http.Client, pageURL, page, decision string) *http.Response {
	t.Helper()
	action := extractAttr(page, "action")
	if action == "" {
		t.Fatalf("no form action in %s", page)
	}
	if !strings.HasPrefix(action, "http") {
		u, _ := url.Parse(pageURL)
		action = u.Scheme + "://" + u.Host + action
	}
	// Extract hidden inputs.
	form := url.Values{}
	for _, field := range []string{"state", "nonce", "flow_id"} {
		if v := extractHidden(page, field); v != "" {
			form.Set(field, v)
		}
	}
	form.Set("decision", decision)
	resp, err := c.PostForm(action, form)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func extractAttr(page, attr string) string {
	i := strings.Index(page, "action=\"")
	if i < 0 {
		return ""
	}
	rest := page[i+len("action=\""):]
	j := strings.Index(rest, "\"")
	return rest[:j]
}

func extractHidden(page, name string) string {
	key := "name=\"" + name + "\" value=\""
	i := strings.Index(page, key)
	if i < 0 {
		// Try reversed order (value before name).
		key2 := "value=\""
		_ = key2
		return ""
	}
	rest := page[i+len(key):]
	j := strings.Index(rest, "\"")
	return rest[:j]
}

func TestFlowHappyPath(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.store.Load(ctx, e.guild); err != nil {
		t.Fatal(err)
	}
	e.loginDiscord(t, "u1")
	e.loginGoogle(t, map[string]any{"sub": "s1", "email": "a@example.com", "name": "A", "hd": "example.com", "email_verified": true})
	e.member(t, "u1", []string{"888", "777"})

	status, body := e.driveFlow(t, true, true)
	if status != 200 || !strings.Contains(body, "Verification complete") {
		t.Fatalf("status %d body %s", status, body)
	}
	d, err := e.store.Load(ctx, e.guild)
	if err != nil {
		t.Fatal(err)
	}
	if d.Members["u1"] == nil || d.Members["u1"].GoogleEmail != "a@example.com" {
		t.Fatalf("link missing: %+v", d.Members)
	}
}

// TestFlowPolicyRejections covers every browser-flow rejection driven by
// organization policy or membership: each case must render the rejection
// page (never raw OAuth internals) and store no durable state.
func TestFlowPolicyRejections(t *testing.T) {
	cases := []struct {
		name     string
		user     string
		member   bool
		google   map[string]any
		wantBody string
	}{
		{
			name:     "non-member",
			user:     "outsider",
			member:   false,
			google:   map[string]any{"sub": "s2", "email": "a@example.com", "hd": "example.com", "email_verified": true},
			wantBody: "not currently a member",
		},
		{
			name:     "unapproved-domain",
			user:     "u1",
			member:   true,
			google:   map[string]any{"sub": "s3", "email": "a@evil.com", "hd": "evil.com", "email_verified": true},
			wantBody: "approved organization",
		},
		{
			name:     "consumer-no-hd",
			user:     "u1",
			member:   true,
			google:   map[string]any{"sub": "s4", "email": "a@gmail.com", "email_verified": true},
			wantBody: "approved organization",
		},
		{
			name:     "unverified-email",
			user:     "u1",
			member:   true,
			google:   map[string]any{"sub": "s5", "email": "a@example.com", "hd": "example.com", "email_verified": false},
			wantBody: "not verified",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			ctx := context.Background()
			if _, err := e.store.Load(ctx, e.guild); err != nil {
				t.Fatal(err)
			}
			e.loginDiscord(t, tc.user)
			e.loginGoogle(t, tc.google)
			if tc.member {
				e.member(t, tc.user, nil)
			}
			status, body := e.driveFlow(t, true, true)
			if status != http.StatusForbidden || !strings.Contains(body, tc.wantBody) {
				t.Fatalf("status %d body %s", status, body)
			}
			d, err := e.store.Load(ctx, e.guild)
			if err != nil {
				t.Fatal(err)
			}
			if len(d.Members) != 0 || len(d.Pending) != 0 {
				t.Fatalf("rejected attempt stored durable state: %+v", d)
			}
		})
	}
}

func TestFlowCancellation(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.store.Load(context.Background(), e.guild); err != nil {
		t.Fatal(err)
	}
	e.loginDiscord(t, "u1")
	e.loginGoogle(t, map[string]any{"sub": "s", "email": "a@example.com", "hd": "example.com", "email_verified": true})
	e.member(t, "u1", nil)
	// Cancel at the Discord step.
	status, body := e.driveFlow(t, false, false)
	if !strings.Contains(body, "cancelled") {
		t.Fatalf("expected cancellation page, got %d %s", status, body)
	}
	// A fresh attempt works afterwards.
	status, body = e.driveFlow(t, true, true)
	if status != 200 || !strings.Contains(body, "Verification complete") {
		t.Fatalf("fresh attempt failed: %d %s", status, body)
	}
}

func TestFlowReplayRejected(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.store.Load(context.Background(), e.guild); err != nil {
		t.Fatal(err)
	}
	e.loginDiscord(t, "u1")
	e.loginGoogle(t, map[string]any{"sub": "s", "email": "a@example.com", "hd": "example.com", "email_verified": true})
	e.member(t, "u1", nil)

	c := noRedirect()
	resp := get(t, c, e.app.URL+"/verify")
	loc := resp.Header.Get("Location")
	page := getBody(t, c, loc)
	resp = submitForm(t, c, loc, page, "approve")
	cbURL := resp.Header.Get("Location")
	// Visit the Discord callback twice: the second is a replay.
	r1 := get(t, c, cbURL)
	googleLoc := r1.Header.Get("Location")
	r2 := get(t, c, cbURL)
	if r2.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay accepted: %d", r2.StatusCode)
	}
	// Continue the original flow to completion.
	page = getBody(t, c, googleLoc)
	resp = submitForm(t, c, googleLoc, page, "approve")
	gcb := resp.Header.Get("Location")
	final := get(t, c, gcb)
	if final.StatusCode != 200 || !strings.Contains(getBodyString(t, final), "Verification complete") {
		t.Fatalf("flow did not complete: %d %s", final.StatusCode, getBodyString(t, final))
	}
	// Replay the Google callback: rejected.
	replay := get(t, c, gcb)
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("google replay accepted: %d", replay.StatusCode)
	}
}

func TestFlowWrongStateRejected(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.store.Load(context.Background(), e.guild); err != nil {
		t.Fatal(err)
	}
	resp := get(t, noRedirect(), e.app.URL+"/callback/discord?code=x&state=forged")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged state accepted: %d", resp.StatusCode)
	}
}

func TestLogsNeverContainOAuthMaterial(t *testing.T) {
	e := newTestEnv(t)
	if _, err := e.store.Load(context.Background(), e.guild); err != nil {
		t.Fatal(err)
	}
	e.loginDiscord(t, "u1")
	e.loginGoogle(t, map[string]any{"sub": "s", "email": "a@example.com", "hd": "example.com", "email_verified": true})
	e.member(t, "u1", nil)
	e.driveFlow(t, true, true)

	// Collect every secret the providers issued.
	var secrets []string
	for _, s := range e.discordS.DumpIssuedSecrets() {
		if s != "" {
			secrets = append(secrets, s)
		}
	}
	for _, s := range e.googleS.DumpIssuedSecrets() {
		if s != "" {
			secrets = append(secrets, s)
		}
	}
	if len(secrets) == 0 {
		t.Fatal("no secrets issued; test setup broken")
	}
	logs := e.logBuf.String()
	for _, s := range secrets {
		if strings.Contains(logs, s) {
			t.Fatalf("log redaction failure: %q appears in logs", s[:min(16, len(s))])
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
