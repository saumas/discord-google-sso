package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// interactionPayload mirrors the Discord interaction JSON the server parses.
type interactionPayload struct {
	Type          int    `json:"type"`
	Token         string `json:"token"`
	ApplicationID string `json:"application_id"`
	Data          *struct {
		Name    string `json:"name"`
		Options []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"options"`
	} `json:"data"`
	Member *struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Roles []string `json:"roles"`
	} `json:"member"`
}

// postInteraction builds, signs, and posts an interaction request and
// returns the HTTP status and response body.
func (e *env) postInteraction(p *interactionPayload) (int, string, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return 0, "", err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := ed25519.Sign(e.priv, append([]byte(ts), body...))
	req, err := http.NewRequest("POST", e.appURL+"/interactions", bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-Timestamp", ts)
	req.Header.Set("X-Signature-Ed25519", hex.EncodeToString(sig))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

// revokeCommand builds a /revoke interaction for target, issued by caller
// (with the given roles).
func revokeCommand(target, caller string, callerRoles []string) *interactionPayload {
	p := &interactionPayload{
		Type:          2,
		Token:         fmt.Sprintf("itoken-%d", rand.Int63()),
		ApplicationID: "e2e-app-id",
	}
	p.Data = &struct {
		Name    string `json:"name"`
		Options []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"options"`
	}{Name: "revoke", Options: []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}{{Name: "member", Value: target}}}
	p.Member = &struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Roles []string `json:"roles"`
	}{}
	p.Member.User.ID = caller
	p.Member.Roles = callerRoles
	return p
}

// followups returns the recorded interaction follow-ups from the simulator.
func (e *env) followups() []string {
	dump := e.discDump()
	if raw, ok := dump["followups"].([]any); ok {
		var out []string
		for _, f := range raw {
			out = append(out, fmt.Sprint(f))
		}
		return out
	}
	return nil
}

// waitFollowup waits until at least n follow-ups are recorded, and one of
// them contains substr (empty matches any).
func (e *env) waitFollowup(n int, substr string) (string, bool) {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		fs := e.followups()
		if len(fs) >= n {
			for _, f := range fs {
				if substr == "" || contains(f, substr) {
					return f, true
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", false
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOfStr(s, sub) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
func httpNewRequest(method, url string, body []byte) (*http.Request, error) {
	return http.NewRequest(method, url, bytes.NewReader(body))
}
func httpDefaultClient() *http.Client { return http.DefaultClient }
