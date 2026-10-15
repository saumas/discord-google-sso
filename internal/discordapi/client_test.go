package discordapi

import (
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestVerifyInteractionRequest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)
	body := []byte(`{"type":1}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := hex.EncodeToString(ed25519.Sign(priv, append([]byte(ts), body...)))

	if err := VerifyInteractionRequest(pubHex, ts, sig, body); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifyInteractionRequest(pubHex, ts, sig, []byte(`{"type":2}`)); err == nil {
		t.Fatal("tampered body accepted")
	}
	if err := VerifyInteractionRequest(pubHex, ts, "00"+sig[2:], body); err == nil {
		t.Fatal("wrong signature accepted")
	}
	old := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	oldSig := hex.EncodeToString(ed25519.Sign(priv, append([]byte(old), body...)))
	if err := VerifyInteractionRequest(pubHex, old, oldSig, body); err == nil {
		t.Fatal("stale timestamp accepted")
	}
}

func TestClientMemberLookup(t *testing.T) {
	joined := "2026-10-01T12:00:00.936000+00:00"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/v10/guilds/g/members/known":
			_, _ = w.Write([]byte(`{"user":{"id":"known"},"joined_at":"` + joined + `","roles":["1"]}`))
		case r.Method == "GET" && r.URL.Path == "/api/v10/guilds/g/members/gone":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Unknown Member","code":10007}`))
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "bot", "cid", "csecret", "cb", nil)

	m, err := c.GetMember(t.Context(), "g", "known")
	if err != nil || m.NotFound || m.JoinedAt.IsZero() {
		t.Fatalf("known member: %+v %v", m, err)
	}
	if want := "2026-10-01 12:00:00.936 +0000 UTC"; m.JoinedAt.String() != want {
		t.Fatalf("joined_at parsed as %s", m.JoinedAt)
	}
	m, err = c.GetMember(t.Context(), "g", "gone")
	if err != nil || !m.NotFound {
		t.Fatalf("gone member: %+v %v", m, err)
	}
	if _, err := c.GetMember(t.Context(), "g", "x"); err == nil {
		t.Fatal("expected error on 418")
	}
}
