// Package discordapi implements the Discord client: OAuth code exchange,
// guild member lookup, role mutation with rate-limit honoring, guild-scoped
// slash-command registration, and interaction response follow-ups. It speaks
// plain HTTP against the configured base URL.
package discordapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// APIError is a Discord API error after internal retries were exhausted.
// Permanent errors (e.g. role hierarchy or missing permission 403s) will not
// resolve by retrying; transient ones may.
type APIError struct {
	Op        string
	Status    int
	Body      string
	Permanent bool
}

func (e *APIError) Error() string {
	perm := "transient"
	if e.Permanent {
		perm = "permanent"
	}
	return fmt.Sprintf("discord %s failed: status %d (%s): %s", e.Op, e.Status, perm, e.Body)
}

// IsPermanent reports whether err is a permanent Discord API failure.
func IsPermanent(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Permanent
}

const (
	maxAttempts  = 4
	requestPause = 250 * time.Millisecond
	maxBodyLog   = 200
)

// Client is a Discord API client.
type Client struct {
	baseURL      string
	botToken     string
	clientID     string
	clientSecret string
	callbackURL  string
	hc           *http.Client
	log          *slog.Logger
}

// New returns a Client for the given base URL and credentials.
func New(baseURL, botToken, clientID, clientSecret, callbackURL string, log *slog.Logger) *Client {
	if log == nil {
		log = slog.Default()
	}
	return &Client{
		baseURL:      baseURL,
		botToken:     botToken,
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURL:  callbackURL,
		hc:           &http.Client{Timeout: 15 * time.Second},
		log:          log,
	}
}

// AuthorizeURL builds the Discord OAuth authorize redirect.
func (c *Client) AuthorizeURL(state string) string {
	q := url.Values{
		"client_id":     {c.clientID},
		"redirect_uri":  {c.callbackURL},
		"response_type": {"code"},
		"scope":         {"identify"},
		"state":         {state},
	}
	return c.baseURL + "/oauth2/authorize?" + q.Encode()
}

type oauthTokenResp struct {
	AccessToken string `json:"access_token"`
}

// ExchangeCode exchanges an OAuth authorization code for a user access token.
func (c *Client) ExchangeCode(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.callbackURL},
	}
	// Response bodies are never logged for token endpoints.
	status, body, err := c.request(ctx, "POST", "/api/oauth2/token", "oauth-exchange", "", "application/x-www-form-urlencoded", []byte(form.Encode()), noLogBody)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", &APIError{Op: "oauth-exchange", Status: status, Body: "token endpoint rejected the exchange", Permanent: status/100 == 4 && status != http.StatusTooManyRequests}
	}
	var tr oauthTokenResp
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", &APIError{Op: "oauth-exchange", Status: http.StatusBadGateway, Body: "invalid token response", Permanent: false}
	}
	return tr.AccessToken, nil
}

type userResp struct {
	ID string `json:"id"`
}

// GetCurrentUser returns the user ID behind an OAuth access token.
func (c *Client) GetCurrentUser(ctx context.Context, accessToken string) (string, error) {
	status, body, err := c.request(ctx, "GET", "/api/users/@me", "identify", "Bearer "+accessToken, "", nil, noLogBody)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", &APIError{Op: "identify", Status: status, Body: "identify call rejected", Permanent: false}
	}
	var u userResp
	if err := json.Unmarshal(body, &u); err != nil || u.ID == "" {
		return "", &APIError{Op: "identify", Status: status, Body: "invalid user response", Permanent: false}
	}
	return u.ID, nil
}

// MemberInfo is the result of a guild member lookup. JoinedAt is zero when
// the API returned the member without a usable joined_at.
type MemberInfo struct {
	NotFound bool
	JoinedAt time.Time
}

type memberResp struct {
	JoinedAt string `json:"joined_at"`
}

// GetMember looks up a guild member and their joined_at timestamp.
func (c *Client) GetMember(ctx context.Context, guildID, userID string) (MemberInfo, error) {
	status, body, err := c.request(ctx, "GET", "/api/guilds/"+guildID+"/members/"+userID, "member-get", "Bot "+c.botToken, "", nil, logBody)
	if err != nil {
		return MemberInfo{}, err
	}
	switch {
	case status == http.StatusNotFound:
		return MemberInfo{NotFound: true}, nil
	case status != http.StatusOK:
		return MemberInfo{}, &APIError{Op: "member-get", Status: status, Body: bodySnippet(body), Permanent: status/100 == 4 && status != http.StatusTooManyRequests}
	}
	var m memberResp
	if err := json.Unmarshal(body, &m); err != nil {
		return MemberInfo{}, &APIError{Op: "member-get", Status: status, Body: "invalid member response", Permanent: false}
	}
	if m.JoinedAt == "" {
		// No usable joined_at: the caller fails safely rather than relying
		// on a missing reconciliation anchor.
		return MemberInfo{}, nil
	}
	t, err := time.Parse(time.RFC3339, m.JoinedAt)
	if err != nil {
		return MemberInfo{}, &APIError{Op: "member-get", Status: status, Body: "unparseable joined_at", Permanent: false}
	}
	return MemberInfo{JoinedAt: t.UTC()}, nil
}

// AddRole adds a role to a guild member.
func (c *Client) AddRole(ctx context.Context, guildID, userID, roleID string) error {
	return c.statusCall(ctx, "PUT", "/api/guilds/"+guildID+"/members/"+userID+"/roles/"+roleID, "role-add", "role add")
}

// RemoveRole removes a role from a guild member.
func (c *Client) RemoveRole(ctx context.Context, guildID, userID, roleID string) error {
	return c.statusCall(ctx, "DELETE", "/api/guilds/"+guildID+"/members/"+userID+"/roles/"+roleID, "role-remove", "role remove")
}

func (c *Client) statusCall(ctx context.Context, method, path, op, desc string) error {
	status, body, err := c.request(ctx, method, path, op, "Bot "+c.botToken, "", nil, logBody)
	if err != nil {
		return err
	}
	if status/100 == 2 {
		return nil
	}
	return &APIError{Op: op, Status: status, Body: bodySnippet(body), Permanent: status/100 == 4 && status != http.StatusTooManyRequests}
}

type applicationCommand struct {
	Name                     string   `json:"name"`
	Description              string   `json:"description"`
	DefaultMemberPermissions *string  `json:"default_member_permissions"`
	Options                  []option `json:"options"`
}

type option struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        int    `json:"type"` // 6 = USER
	Required    bool   `json:"required"`
}

// RevokeCommandName is the slash command registered for revocation.
const RevokeCommandName = "revoke"

// RegisterRevokeCommand ensures the guild-scoped /revoke slash command
// exists. It is idempotent: PUT replaces the guild's full command set with
// exactly this command.
func (c *Client) RegisterRevokeCommand(ctx context.Context, guildID string) error {
	noPerms := "0"
	cmds := []applicationCommand{{
		Name:                     RevokeCommandName,
		Description:              "Revoke a member's verified identity link and restore unverified roles",
		DefaultMemberPermissions: &noPerms,
		Options: []option{{
			Name:        "member",
			Description: "Member whose verification to revoke",
			Type:        6, // USER
			Required:    true,
		}},
	}}
	body, err := json.Marshal(cmds)
	if err != nil {
		return err
	}
	status, respBody, err := c.request(ctx, "PUT", "/api/applications/"+c.clientID+"/guilds/"+guildID+"/commands", "command-register", "Bot "+c.botToken, "application/json", body, logBody)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return &APIError{Op: "command-register", Status: status, Body: bodySnippet(respBody), Permanent: status/100 == 4 && status != http.StatusTooManyRequests}
	}
	return nil
}

// PatchInteractionResponse delivers the final outcome of an interaction on
// its channel via the interaction webhook.
func (c *Client) PatchInteractionResponse(ctx context.Context, applicationID, interactionToken, content string) error {
	payload := map[string]any{"content": content}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	path := "/api/webhooks/" + applicationID + "/" + interactionToken + "/messages/@original"
	status, respBody, err := c.request(ctx, http.MethodPatch, path, "interaction-followup", "", "application/json", body, logBody)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return &APIError{Op: "interaction-followup", Status: status, Body: bodySnippet(respBody), Permanent: status/100 == 4}
	}
	return nil
}

// bodyLogPolicy controls whether response bodies may appear in error text.
type bodyLogPolicy int

const (
	logBody bodyLogPolicy = iota
	noLogBody
)

func bodySnippet(b []byte) string {
	s := string(b)
	if len(s) > maxBodyLog {
		s = s[:maxBodyLog]
	}
	return s
}

// request performs an HTTP call with rate-limit honoring and bounded retry.
// 429 responses honor retry_after; 5xx and network errors back off and
// retry; 4xx are permanent (except 429).
func (c *Client) request(ctx context.Context, method, path, op, auth, contentType string, body []byte, bodyPolicy bodyLogPolicy) (int, []byte, error) {
	var lastErr error
	for attempt := range maxAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(backoff(attempt)):
			}
		}
		status, respBody, err := c.once(ctx, method, path, auth, contentType, body)
		if err == nil {
			if status != http.StatusTooManyRequests {
				return status, respBody, nil
			}
			// Rate limited: honor retry_after from the response body.
			retryAfter := parseRetryAfter(respBody)
			c.log.Warn("discord rate limited", "op", op, "attempt", attempt+1, "retry_after_ms", retryAfter.Milliseconds())
			lastErr = &APIError{Op: op, Status: status, Body: "rate limited", Permanent: false}
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(retryAfter):
			}
			continue
		}
		lastErr = err
		// Network errors and 5xx are transient: retry.
		c.log.Warn("discord request failed", "op", op, "attempt", attempt+1, "error", err.Error())
	}
	return 0, nil, lastErr
}

func backoff(attempt int) time.Duration {
	d := requestPause * time.Duration(1<<uint(attempt-1))
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	return d
}

func parseRetryAfter(body []byte) time.Duration {
	var r struct {
		RetryAfter float64 `json:"retry_after"`
	}
	if err := json.Unmarshal(body, &r); err == nil && r.RetryAfter > 0 && r.RetryAfter < 10 {
		return time.Duration(r.RetryAfter * float64(time.Second))
	}
	return time.Second
}

func (c *Client) once(ctx context.Context, method, path, auth, contentType string, body []byte) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBody, nil
}
