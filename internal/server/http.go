// Package server implements the HTTP surface: verification start and
// callbacks, the Discord interaction endpoint (signature + admin
// criterion), and health/readiness.
package server

import (
	"context"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/saumas/discord-google-sso/internal/config"
	"github.com/saumas/discord-google-sso/internal/core"
	"github.com/saumas/discord-google-sso/internal/discordapi"
	"github.com/saumas/discord-google-sso/internal/googleoidc"
	"github.com/saumas/discord-google-sso/internal/session"
)

// Server is the application HTTP server.
type Server struct {
	cfg      *config.Config
	core     *core.Service
	discord  *discordapi.Client
	google   *googleoidc.Client
	sessions *session.Manager
	log      *slog.Logger
	ready    atomic.Bool
	http     *http.Server
}

// New builds the server.
func New(cfg *config.Config, svc *core.Service, d *discordapi.Client, g *googleoidc.Client, sessions *session.Manager, log *slog.Logger) *Server {
	s := &Server{cfg: cfg, core: svc, discord: d, google: g, sessions: sessions, log: log}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /verify", s.handleVerifyStart)
	mux.HandleFunc("GET /callback/discord", s.handleDiscordCallback)
	mux.HandleFunc("GET /callback/google", s.handleGoogleCallback)
	mux.HandleFunc("POST /interactions", s.handleInteraction)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if s.ready.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ready"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/verify", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})
	s.http = &http.Server{Addr: cfg.ListenAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return s
}

// Handler returns the HTTP handler (mountable on any server).
func (s *Server) Handler() http.Handler { return s.http.Handler }

// SetReady flips the readiness gate (configuration validated and state
// Secret loaded). Provider unavailability never evicts readiness.
func (s *Server) SetReady(v bool) { s.ready.Store(v) }

// ListenAndServe runs the server until the context is canceled; shutdown is
// graceful.
func (s *Server) ListenAndServe(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.http.Shutdown(shCtx)
	}
}

func (s *Server) handleVerifyStart(w http.ResponseWriter, r *http.Request) {
	sess := s.sessions.Start()
	http.Redirect(w, r, s.discord.AuthorizeURL(sess.DiscordState), http.StatusFound)
}

type pageData struct {
	Title string
	Body  string
	Retry bool
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>{{.Title}}</title>
<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem}p{line-height:1.5}</style>
</head><body><h1>{{.Title}}</h1><p>{{.Body}}</p>
{{if .Retry}}<p><a href="/verify">Start verification again</a></p>{{end}}
</body></html>`))

func (s *Server) render(w http.ResponseWriter, status int, title, body string, retry bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pageTmpl.Execute(w, pageData{Title: title, Body: body, Retry: retry})
}

func (s *Server) reject(w http.ResponseWriter, reason string) {
	// Human-readable reason; never raw OAuth internals.
	s.render(w, http.StatusForbidden, "Verification unsuccessful", reason, true)
}

func (s *Server) handleDiscordCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("error") != "" {
		s.render(w, http.StatusOK, "Verification cancelled", "You cancelled the Discord authorization step. You can start again at any time.", true)
		return
	}
	sess, err := s.sessions.Consume(q.Get("state"), session.StageDiscord)
	if err != nil {
		s.render(w, http.StatusBadRequest, "Session invalid", "This verification link was already used or has expired. Please start again.", true)
		return
	}
	code := q.Get("code")
	if code == "" {
		s.render(w, http.StatusBadRequest, "Verification unsuccessful", "The Discord authorization response was missing required data. Please start again.", true)
		return
	}
	token, err := s.discord.ExchangeCode(r.Context(), code)
	if err != nil {
		s.log.Warn("discord code exchange failed", "error", err.Error())
		s.render(w, http.StatusBadGateway, "Temporary error", "A temporary error occurred while contacting Discord. Please try the verification link again.", true)
		return
	}
	memberID, err := s.discord.GetCurrentUser(r.Context(), token)
	if err != nil {
		s.log.Warn("discord identify failed", "error", err.Error())
		s.render(w, http.StatusBadGateway, "Temporary error", "A temporary error occurred while contacting Discord. Please try the verification link again.", true)
		return
	}
	// Membership check before proceeding to the Google step.
	info, err := s.discord.GetMember(r.Context(), s.cfg.GuildID, memberID)
	if err != nil {
		s.log.Warn("membership check failed", "member", memberID, "error", err.Error())
		s.render(w, http.StatusBadGateway, "Temporary error", "A temporary error occurred while checking your membership. Please try the verification link again.", true)
		return
	}
	if info.NotFound {
		s.reject(w, "You are not currently a member of this server, so verification cannot continue.")
		return
	}
	if info.JoinedAt.IsZero() {
		// A link is never stored without its reconciliation anchor.
		s.render(w, http.StatusBadGateway, "Temporary error", "Your membership information is temporarily unavailable. Please try the verification link again.", true)
		return
	}
	// Capture the current revocation epoch now that the Discord identity is
	// established.
	doc, err := s.core.LoadDoc(r.Context())
	if err != nil {
		s.log.Error("state load for epoch capture failed", "error", err.Error())
		s.render(w, http.StatusInternalServerError, "Temporary error", "A temporary error occurred. Please try the verification link again.", true)
		return
	}
	s.sessions.SetMember(sess.DiscordState, memberID, doc.Epoch(memberID), info.JoinedAt)

	authURL, err := s.google.AuthorizeURL(r.Context(), sess.GoogleState, sess.Nonce)
	if err != nil {
		s.log.Warn("google authorize URL failed", "error", err.Error())
		s.render(w, http.StatusBadGateway, "Temporary error", "A temporary error occurred while contacting Google. Please try the verification link again.", true)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("error") != "" {
		s.render(w, http.StatusOK, "Verification cancelled", "You cancelled the Google authorization step. You can start again at any time.", true)
		return
	}
	sess, err := s.sessions.Consume(q.Get("state"), session.StageGoogle)
	if err != nil {
		s.render(w, http.StatusBadRequest, "Session invalid", "This verification link was already used or has expired. Please start again.", true)
		return
	}
	code := q.Get("code")
	if code == "" {
		s.render(w, http.StatusBadRequest, "Verification unsuccessful", "The Google authorization response was missing required data. Please start again.", true)
		return
	}
	idToken, err := s.google.ExchangeCode(r.Context(), code)
	if err != nil {
		s.log.Warn("google code exchange failed", "error", err.Error())
		s.render(w, http.StatusBadGateway, "Temporary error", "A temporary error occurred while contacting Google. Please try the verification link again.", true)
		return
	}
	claims, err := s.google.ValidateIDToken(r.Context(), idToken, sess.Nonce)
	if err != nil {
		s.log.Warn("google id token validation failed", "error", err.Error())
		s.reject(w, "Your Google identity could not be verified. Please make sure you sign in with your organization account and try again.")
		return
	}
	if !claims.EmailVerified {
		s.reject(w, "The Google account's email address is not verified.")
		return
	}
	if !s.domainAllowed(claims.Hd) {
		s.reject(w, "This server only accepts members with an approved organization Google account.")
		return
	}

	res := s.core.Verify(r.Context(), &core.VerifyInput{
		MemberID:    sess.MemberID,
		Epoch:       sess.Epoch,
		JoinedAt:    sess.JoinedAt,
		GoogleSub:   claims.Sub,
		GoogleName:  claims.Name,
		GoogleEmail: claims.Email,
	})
	switch res.Status {
	case core.VerifyVerified:
		s.render(w, http.StatusOK, "Verification complete", "You are verified. You now have access to the member channels.", false)
	case core.VerifyRejected:
		s.reject(w, res.Reason)
	default:
		s.render(w, http.StatusAccepted, "Verification in progress", res.Reason, true)
	}
}

func (s *Server) domainAllowed(hd string) bool {
	if hd == "" {
		return false
	}
	for _, d := range s.cfg.Google.AllowedDomains {
		if hd == d {
			return true
		}
	}
	return false
}

// --- Discord interactions ---

type interaction struct {
	Type int `json:"type"`
	Data *struct {
		Name    string `json:"name"`
		Options []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"options"`
	} `json:"data"`
	ApplicationID string `json:"application_id"`
	Token         string `json:"token"`
	Member        *struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Roles []string `json:"roles"`
	} `json:"member"`
	User *struct {
		ID string `json:"id"`
	} `json:"user"`
}

const (
	itPing               = 1
	itApplicationCommand = 2
	itRespPong           = 1
	itRespMessage        = 4 // CHANNEL_MESSAGE_WITH_SOURCE
	itRespDefer          = 5 // DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE
)

func (s *Server) handleInteraction(w http.ResponseWriter, r *http.Request) {
	body := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil || len(body) > 1<<20 {
			break
		}
	}
	if err := discordapi.VerifyInteractionRequest(
		s.cfg.Discord.PublicKey,
		r.Header.Get("X-Signature-Timestamp"),
		r.Header.Get("X-Signature-Ed25519"),
		body,
	); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var it interaction
	if err := json.Unmarshal(body, &it); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch it.Type {
	case itPing:
		writeJSON(w, http.StatusOK, map[string]any{"type": itRespPong})
		return
	case itApplicationCommand:
		if it.Data == nil || it.Data.Name != discordapi.RevokeCommandName {
			writeJSON(w, http.StatusOK, map[string]any{"type": itRespMessage, "data": map[string]any{"content": "Unknown command."}})
			return
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if _, ok := s.authorizeAdmin(&it); !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"type": itRespMessage,
			"data": map[string]any{"content": "You are not authorized to use this command.", "flags": 64},
		})
		return
	}
	var target string
	for _, o := range it.Data.Options {
		if o.Name == "member" {
			target = o.Value
		}
	}
	if target == "" {
		writeJSON(w, http.StatusOK, map[string]any{"type": itRespMessage, "data": map[string]any{"content": "Missing target member."}})
		return
	}
	caller := ""
	if it.Member != nil {
		caller = it.Member.User.ID
	}
	// Acknowledge promptly: the outcome is reported only after the
	// revocation completes, never prematurely.
	writeJSON(w, http.StatusOK, map[string]any{"type": itRespDefer, "data": map[string]any{"content": "Revocation accepted."}})

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		res, err := s.core.Revoke(ctx, target)
		var msg string
		switch {
		case err != nil && res == nil:
			msg = "Revocation failed: could not commit the state change."
			s.log.Error("revoke command commit failed", "target", target, "caller", caller, "error", err.Error())
		case err != nil:
			msg = "Revocation committed; role restoration is still pending and will be applied automatically."
			s.log.Warn("revoke command role restoration pending", "target", target, "caller", caller, "error", err.Error())
		case !res.CreatedRestoreOp:
			msg = "No verified link found for that member; any pending login sessions were invalidated."
		default:
			msg = "Revocation complete: link released and roles restored."
		}
		pctx, pcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer pcancel()
		if err := s.discord.PatchInteractionResponse(pctx, it.ApplicationID, it.Token, msg); err != nil {
			s.log.Warn("revoke outcome follow-up delivery failed", "error", err.Error())
		}
	}()
}

func (s *Server) authorizeAdmin(it *interaction) (string, bool) {
	if it.Member != nil {
		for _, id := range s.cfg.AdminUserIDs {
			if it.Member.User.ID == id {
				return it.Member.User.ID, true
			}
		}
		for _, role := range it.Member.Roles {
			for _, adminRole := range s.cfg.AdminRoleIDs {
				if role == adminRole {
					return it.Member.User.ID, true
				}
			}
		}
	}
	if it.User != nil {
		for _, id := range s.cfg.AdminUserIDs {
			if it.User.ID == id {
				return it.User.ID, true
			}
		}
	}
	return "", false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
