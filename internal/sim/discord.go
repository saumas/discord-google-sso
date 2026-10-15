// Package sim implements the Go-simulated providers used by the Kind E2E
// suite: a Discord OAuth/REST/interactions simulator and a Google OIDC
// simulator. They speak the same HTTP contracts and signature/claim schemes
// as the real providers; the application is configured to point at them via
// provider base URL overrides.
package sim

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Failure is an injected failure for matching requests.
type Failure struct {
	Path    string `json:"path"`   // matched as a substring of the request path
	Method  string `json:"method"` // if set, only this HTTP method matches
	Status  int    `json:"status"`
	Count   int    `json:"count"` // 0 = unlimited
	DelayMS int    `json:"delay_ms"`
	Body    string `json:"body"` // response body written for the failure
}

// ConsentTmpl renders the shared consent page for both simulators.
var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Authorize {{.Provider}}</title></head>
<body><h1>Authorize {{.Provider}}</h1>
<p>Signed in as <code>{{.User}}</code></p>
<form method="POST" action="{{.Action}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="nonce" value="{{.Nonce}}">
<input type="hidden" name="flow_id" value="{{.FlowID}}">
<button id="approve" type="submit" name="decision" value="approve">Approve</button>
<button id="deny" type="submit" name="decision" value="deny">Deny</button>
</form></body></html>`))

type consentData struct {
	Provider string
	User     string
	State    string
	FlowID   string
	Action   string
	Nonce    string
}

func newToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// failureEngine applies injected failures by path substring.
type failureEngine struct {
	mu       sync.Mutex
	failures []Failure
}

func (f *failureEngine) add(fa Failure) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = append(f.failures, fa)
}

// clear removes all injected failures.
func (f *failureEngine) clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = nil
}

// check reports (blocked, status, delay, body). A blocked request should
// return the given status and body after the configured delay.
func (f *failureEngine) check(method, path string) (bool, int, time.Duration, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.failures {
		fa := &f.failures[i]
		if fa.Path != "" && strings.Contains(path, fa.Path) && (fa.Method == "" || fa.Method == method) {
			if fa.Count > 0 {
				fa.Count--
			}
			return true, fa.Status, time.Duration(fa.DelayMS) * time.Millisecond, fa.Body
		}
	}
	return false, 0, 0, ""
}

// gate applies injected failures for the request and reports whether the
// request was blocked (the failure response — status and any configured
// marker body — has already been written).
func (f *failureEngine) gate(w http.ResponseWriter, r *http.Request) bool {
	blocked, status, delay, body := f.check(r.Method, r.URL.Path)
	if !blocked {
		return false
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	w.WriteHeader(status)
	if body != "" {
		_, _ = io.WriteString(w, body)
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// --- Discord simulator ---

// DiscordSim is the Discord provider simulator.
type DiscordSim struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	BotToken     string

	mu sync.Mutex
	// login is the simulated logged-in Discord user.
	login string
	// oauth codes -> user
	codes map[string]string
	// bearer tokens -> user
	bearers map[string]string
	// guildID -> userID -> membership
	members map[string]map[string]*simMember
	// appID -> guildID -> registered commands body
	commands map[string]map[string]json.RawMessage
	// interaction follow-ups recorded
	followups []string
	// secrets ever issued (for log redaction assertions)
	issuedSecrets []string

	failures failureEngine
	log      *slog.Logger
}

type simMember struct {
	JoinedAt time.Time `json:"joined_at"`
	Roles    []string  `json:"roles"`
}

// NewDiscordSim constructs the simulator.
func NewDiscordSim(clientID, clientSecret, redirectURI, botToken string, log *slog.Logger) *DiscordSim {
	return &DiscordSim{
		ClientID: clientID, ClientSecret: clientSecret, RedirectURI: redirectURI, BotToken: botToken,
		codes: map[string]string{}, bearers: map[string]string{},
		members: map[string]map[string]*simMember{}, commands: map[string]map[string]json.RawMessage{},
		log: log,
	}
}

// Handler returns the HTTP handler.
func (d *DiscordSim) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth2/authorize", d.handleAuthorize)
	mux.HandleFunc("POST /oauth2/authorize/decision", d.handleAuthorizeDecision)
	mux.HandleFunc("POST /api/v10/oauth2/token", d.handleToken)
	mux.HandleFunc("GET /api/v10/users/@me", d.handleMe)
	mux.HandleFunc("GET /api/v10/guilds/{gid}/members/{uid}", d.handleGetMember)
	mux.HandleFunc("PUT /api/v10/guilds/{gid}/members/{uid}/roles/{rid}", d.handleRole(true))
	mux.HandleFunc("DELETE /api/v10/guilds/{gid}/members/{uid}/roles/{rid}", d.handleRole(false))
	mux.HandleFunc("GET /api/v10/applications/{aid}/guilds/{gid}/commands", d.handleGetCommands)
	mux.HandleFunc("PUT /api/v10/applications/{aid}/guilds/{gid}/commands", d.handlePutCommands)
	mux.HandleFunc("PATCH /api/v10/webhooks/{aid}/{token}/messages/@original", d.handleFollowup)
	mux.HandleFunc("POST /_admin/reset", d.adminReset)
	mux.HandleFunc("POST /_admin/login-as", d.adminLoginAs)
	mux.HandleFunc("POST /_admin/member", d.adminMember)
	mux.HandleFunc("POST /_admin/kick", d.adminKick)
	mux.HandleFunc("POST /_admin/member-no-joined-at", d.adminMemberNoJoinedAt)
	mux.HandleFunc("POST /_admin/set-roles", d.adminSetRoles)
	mux.HandleFunc("POST /_admin/fail", d.adminFail)
	mux.HandleFunc("POST /_admin/clear-failures", func(w http.ResponseWriter, _ *http.Request) {
		d.failures.clear()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /_admin/dump", d.adminDump)
	return mux
}

func (d *DiscordSim) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if d.failures.gate(w, r) {
		return
	}
	q := r.URL.Query()
	if q.Get("client_id") != d.ClientID || q.Get("redirect_uri") != d.RedirectURI {
		http.Error(w, "invalid client", http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	user := d.login
	d.mu.Unlock()
	if user == "" {
		http.Error(w, "no simulated login", http.StatusUnauthorized)
		return
	}
	_ = consentTmpl.Execute(w, consentData{Provider: "Discord", User: user, State: q.Get("state"), FlowID: "discord", Action: "/oauth2/authorize/decision"})
}

func (d *DiscordSim) handleAuthorizeDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	state := r.FormValue("state")
	q := url.Values{}
	if state != "" {
		q.Set("state", state)
	}
	d.mu.Lock()
	user := d.login
	d.mu.Unlock()
	if r.FormValue("decision") != "approve" {
		q.Set("error", "access_denied")
	} else {
		code := newToken()
		d.mu.Lock()
		d.codes[code] = user
		d.issuedSecrets = append(d.issuedSecrets, code)
		d.mu.Unlock()
		q.Set("code", code)
	}
	http.Redirect(w, r, d.RedirectURI+"?"+q.Encode(), http.StatusFound)
}

func (d *DiscordSim) handleToken(w http.ResponseWriter, r *http.Request) {
	if d.failures.gate(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.FormValue("grant_type") != "authorization_code" ||
		r.FormValue("client_id") != d.ClientID ||
		r.FormValue("client_secret") != d.ClientSecret ||
		r.FormValue("redirect_uri") != d.RedirectURI {
		http.Error(w, `{"error": "invalid_client"}`, http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	d.mu.Lock()
	defer d.mu.Unlock()
	user, ok := d.codes[code]
	if !ok {
		http.Error(w, `{"error": "invalid_grant"}`, http.StatusBadRequest)
		return
	}
	delete(d.codes, code) // single-use
	token := newToken()
	d.bearers[token] = user
	d.issuedSecrets = append(d.issuedSecrets, token)
	writeJSON(w, map[string]any{"access_token": token, "token_type": "Bearer", "scope": "identify"})
}

func (d *DiscordSim) handleMe(w http.ResponseWriter, r *http.Request) {
	if d.failures.gate(w, r) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	auth := r.Header.Get("Authorization")
	if len(auth) <= 7 || auth[:7] != "Bearer " {
		http.Error(w, `{"message": "401: Unauthorized", "code": 0}`, http.StatusUnauthorized)
		return
	}
	user, ok := d.bearers[auth[7:]]
	if !ok {
		http.Error(w, `{"message": "401: Unauthorized", "code": 0}`, http.StatusUnauthorized)
		return
	}
	writeJSON(w, map[string]any{"id": user, "username": "sim-user-" + user})
}

func (d *DiscordSim) guildMember(guildID, userID string) *simMember {
	if d.members[guildID] == nil {
		d.members[guildID] = map[string]*simMember{}
	}
	return d.members[guildID][userID]
}

func (d *DiscordSim) handleGetMember(w http.ResponseWriter, r *http.Request) {
	if d.failures.gate(w, r) {
		return
	}
	if r.Header.Get("Authorization") != "Bot "+d.BotToken {
		http.Error(w, `{"message": "401: Unauthorized", "code": 0}`, http.StatusUnauthorized)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.guildMember(r.PathValue("gid"), r.PathValue("uid"))
	if m == nil {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]any{"message": "Unknown Member", "code": 10007})
		return
	}
	writeJSON(w, map[string]any{
		"user":      map[string]any{"id": r.PathValue("uid")},
		"joined_at": m.JoinedAt.UTC().Format(time.RFC3339Nano),
		"roles":     m.Roles,
	})
}

func (d *DiscordSim) handleRole(add bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.failures.gate(w, r) {
			return
		}
		if r.Header.Get("Authorization") != "Bot "+d.BotToken {
			http.Error(w, `{"message": "401: Unauthorized", "code": 0}`, http.StatusUnauthorized)
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		m := d.guildMember(r.PathValue("gid"), r.PathValue("uid"))
		if m == nil {
			w.WriteHeader(http.StatusNotFound)
			writeJSON(w, map[string]any{"message": "Unknown Member", "code": 10007})
			return
		}
		rid := r.PathValue("rid")
		out := make([]string, 0, len(m.Roles)+1)
		for _, x := range m.Roles {
			if add && x == rid {
				continue // dedupe on add
			}
			if !add && x == rid {
				continue // remove
			}
			out = append(out, x)
		}
		if add {
			out = append(out, rid)
		}
		m.Roles = out
		w.WriteHeader(http.StatusNoContent)
	}
}

func (d *DiscordSim) handleGetCommands(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bot "+d.BotToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	cmds := d.commands[r.PathValue("aid")][r.PathValue("gid")]
	var list []json.RawMessage
	if cmds != nil {
		if err := json.Unmarshal(cmds, &list); err != nil {
			http.Error(w, "bad commands", http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, list)
}

func (d *DiscordSim) handlePutCommands(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bot "+d.BotToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.commands[r.PathValue("aid")] == nil {
		d.commands[r.PathValue("aid")] = map[string]json.RawMessage{}
	}
	d.commands[r.PathValue("aid")][r.PathValue("gid")] = body
	writeJSON(w, body)
}

func (d *DiscordSim) handleFollowup(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	content, _ := body["content"].(string)
	d.followups = append(d.followups, content)
	d.mu.Unlock()
	writeJSON(w, map[string]any{"content": content})
}

// --- admin ---

func (d *DiscordSim) adminReset(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.login = ""
	d.codes = map[string]string{}
	d.bearers = map[string]string{}
	d.members = map[string]map[string]*simMember{}
	d.commands = map[string]map[string]json.RawMessage{}
	d.followups = nil
	d.issuedSecrets = nil
	d.mu.Unlock()
	d.failures.clear()
	w.WriteHeader(http.StatusNoContent)
}

func (d *DiscordSim) adminLoginAs(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	d.mu.Lock()
	d.login = req.UserID
	d.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (d *DiscordSim) adminMember(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID   string   `json:"user_id"`
		GuildID  string   `json:"guild_id"`
		JoinedAt string   `json:"joined_at"` // RFC3339; defaults to now
		Roles    []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	joined := time.Now().UTC().Add(-24 * time.Hour)
	if req.JoinedAt != "" {
		var err error
		joined, err = time.Parse(time.RFC3339, req.JoinedAt)
		if err != nil {
			http.Error(w, "bad joined_at", http.StatusBadRequest)
			return
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.members[req.GuildID] == nil {
		d.members[req.GuildID] = map[string]*simMember{}
	}
	d.members[req.GuildID][req.UserID] = &simMember{JoinedAt: joined, Roles: req.Roles}
	w.WriteHeader(http.StatusNoContent)
}

func (d *DiscordSim) adminKick(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID  string `json:"user_id"`
		GuildID string `json:"guild_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	d.mu.Lock()
	defer d.mu.Unlock()
	if g := d.members[req.GuildID]; g != nil {
		delete(g, req.UserID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// adminMemberNoJoinedAt installs a member whose lookup returns no usable
// joined_at (the caller fails safely; used to test the anchor invariant).
func (d *DiscordSim) adminMemberNoJoinedAt(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID  string   `json:"user_id"`
		GuildID string   `json:"guild_id"`
		Roles   []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.members[req.GuildID] == nil {
		d.members[req.GuildID] = map[string]*simMember{}
	}
	d.members[req.GuildID][req.UserID] = &simMember{Roles: req.Roles}
	w.WriteHeader(http.StatusNoContent)
}

// adminSetRoles replaces a member's roles WITHOUT touching joined_at, so
// tests can simulate manual role changes without a spurious rejoin.
func (d *DiscordSim) adminSetRoles(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID  string   `json:"user_id"`
		GuildID string   `json:"guild_id"`
		Roles   []string `json:"roles"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.guildMember(req.GuildID, req.UserID)
	if m == nil {
		http.Error(w, "unknown member", http.StatusNotFound)
		return
	}
	m.Roles = append([]string(nil), req.Roles...)
	w.WriteHeader(http.StatusNoContent)
}

func (d *DiscordSim) adminFail(w http.ResponseWriter, r *http.Request) {
	var f Failure
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d.failures.add(f)
	w.WriteHeader(http.StatusNoContent)
}

// DiscordDump is the simulators observable state for assertions.
type DiscordDump struct {
	Login         string                                `json:"login"`
	Members       map[string]map[string]*simMember      `json:"members"`
	Followups     []string                              `json:"followups"`
	Commands      map[string]map[string]json.RawMessage `json:"commands"`
	IssuedSecrets []string                              `json:"issued_secrets"`
}

// DumpIssuedSecrets returns every OAuth code, token, and ID token the
// simulator has issued (for log-redaction assertions).
func (d *DiscordSim) DumpIssuedSecrets() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.issuedSecrets...)
}

func (d *DiscordSim) adminDump(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	writeJSON(w, DiscordDump{Login: d.login, Members: d.members, Followups: d.followups, Commands: d.commands, IssuedSecrets: d.issuedSecrets})
}
