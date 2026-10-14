package server

import (
	"context"
	"strings"
	"testing"
)

// discFail injects a Discord sim failure and registers cleanup.
func (e *testEnv) discFail(t *testing.T, failure map[string]any) {
	t.Helper()
	post(t, e.client, e.discordH.URL+"/_admin/fail", failure)
	t.Cleanup(func() { post(t, e.client, e.discordH.URL+"/_admin/clear-failures", nil) })
}

// driveDiscordLeg walks the flow through the Discord consent and returns the
// body of the app's Discord callback response.
func (e *testEnv) driveDiscordLeg(t *testing.T) string {
	t.Helper()
	c := noRedirect()
	resp := get(t, c, e.app.URL+"/verify")
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, e.discordH.URL) {
		t.Fatalf("expected Discord authorize redirect, got %s", loc)
	}
	page := getBody(t, c, loc)
	resp = submitForm(t, c, loc, page, "approve")
	loc = resp.Header.Get("Location")
	if !strings.HasPrefix(loc, e.app.URL+"/callback/discord") {
		t.Fatalf("expected app discord callback, got %s", loc)
	}
	return getBody(t, c, loc)
}

// TestPreGrantTransientFailuresFailSafely covers the spec's pre-grant
// failure branches: a transient provider error at any pre-grant step must
// fail safely — no link, no roles, no durable record beyond the session —
// and show a clear retry message.
func TestPreGrantTransientFailuresFailSafely(t *testing.T) {
	cases := []struct {
		name string
		fail map[string]any
	}{
		{
			name: "discord token exchange 5xx with marker body",
			fail: map[string]any{"path": "/api/v10/oauth2/token", "status": 500, "body": "SECRET-MARKER-do-not-log"},
		},
		{
			name: "discord identify 5xx",
			fail: map[string]any{"path": "/api/v10/users/@me", "status": 500},
		},
		{
			name: "membership lookup 5xx (non-404)",
			fail: map[string]any{"path": "/api/v10/guilds/", "status": 503},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newTestEnv(t)
			ctx := context.Background()
			if _, err := e.store.Load(ctx, e.guild); err != nil {
				t.Fatal(err)
			}
			e.loginDiscord(t, "u1")
			e.loginGoogle(t, map[string]any{"sub": "s1", "email": "a@example.com", "name": "A", "hd": "example.com", "email_verified": true})
			e.member(t, "u1", []string{"888", "889", "777"})
			e.discFail(t, tc.fail)

			body := e.driveDiscordLeg(t)
			if !strings.Contains(body, "temporary error occurred") {
				t.Fatalf("expected safe retry page, got: %q", clip(body, 200))
			}
			d, err := e.store.Load(ctx, e.guild)
			if err != nil {
				t.Fatal(err)
			}
			if len(d.Members) != 0 || len(d.Pending) != 0 {
				t.Fatalf("pre-grant failure stored durable state: %+v", d)
			}
		})
	}
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// TestTokenEndpointMarkerNeverLogged extends the redaction guarantee to the
// error path: a 5xx from the Discord token endpoint carrying marker material
// must not put the marker into the emitted logs.
func TestTokenEndpointMarkerNeverLogged(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.store.Load(ctx, e.guild); err != nil {
		t.Fatal(err)
	}
	e.loginDiscord(t, "u1")
	e.loginGoogle(t, map[string]any{"sub": "s1", "email": "a@example.com", "name": "A", "hd": "example.com", "email_verified": true})
	e.member(t, "u1", nil)
	e.discFail(t, map[string]any{"path": "/api/v10/oauth2/token", "status": 500, "body": "SECRET-MARKER-do-not-log"})

	body := e.driveDiscordLeg(t)
	if !strings.Contains(body, "temporary error occurred") {
		t.Fatalf("expected retry page, got %q", clip(body, 200))
	}
	if strings.Contains(e.logBuf.String(), "SECRET-MARKER-do-not-log") {
		t.Fatal("token-endpoint error body leaked into logs")
	}
}

// TestMemberWithoutJoinedAtFailsSafely covers the reconciliation-anchor
// invariant: a member lookup returning present-but-no-joined_at must never
// store a link.
func TestMemberWithoutJoinedAtFailsSafely(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.store.Load(ctx, e.guild); err != nil {
		t.Fatal(err)
	}
	e.loginDiscord(t, "u1")
	e.loginGoogle(t, map[string]any{"sub": "s1", "email": "a@example.com", "name": "A", "hd": "example.com", "email_verified": true})
	post(t, e.client, e.discordH.URL+"/_admin/member-no-joined-at", map[string]any{
		"user_id": "u1", "guild_id": e.guild, "roles": []string{"888"},
	})

	body := e.driveDiscordLeg(t)
	if !strings.Contains(body, "temporarily unavailable") {
		t.Fatalf("expected anchor-unavailable page, got %q", clip(body, 200))
	}
	d, err := e.store.Load(ctx, e.guild)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Members) != 0 || len(d.Pending) != 0 {
		t.Fatalf("link stored without reconciliation anchor: %+v", d.Members)
	}
}

// TestGoogleTokenExchangeFailureFailsSafely covers the Google pre-grant
// exchange failure.
func TestGoogleTokenExchangeFailureFailsSafely(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.store.Load(ctx, e.guild); err != nil {
		t.Fatal(err)
	}
	e.loginDiscord(t, "u1")
	e.loginGoogle(t, map[string]any{"sub": "s1", "email": "a@example.com", "name": "A", "hd": "example.com", "email_verified": true})
	e.member(t, "u1", nil)
	post(t, e.client, e.googleH.URL+"/_admin/fail", map[string]any{"path": "/token", "status": 500})
	t.Cleanup(func() { post(t, e.client, e.googleH.URL+"/_admin/clear-failures", nil) })

	_, body := e.driveFlow(t, true, true)
	if !strings.Contains(body, "temporary error occurred") {
		t.Fatalf("expected retry page, got %q", clip(body, 200))
	}
	d, err := e.store.Load(ctx, e.guild)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Members) != 0 || len(d.Pending) != 0 {
		t.Fatalf("google exchange failure stored durable state: %+v", d)
	}
}
