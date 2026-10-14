package discordapi

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNoLogBodySuppressesTokenEndpointBody asserts the enforced redaction
// policy: when the OAuth token endpoint keeps failing with 5xx, the returned
// error (which flows into logs) must not carry any response-body material.
func TestNoLogBodySuppressesTokenEndpointBody(t *testing.T) {
	const marker = "SECRET-MARKER-dont-leak-me"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"server_error","hint":"` + marker + `"}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "bot", "cid", "csecret", "cb", slog.Default())

	_, err := c.ExchangeCode(context.Background(), "some-code")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatalf("token-endpoint response body leaked into error: %v", err)
	}
	if strings.Contains(err.Error(), "server_error") {
		t.Fatalf("token-endpoint response body leaked into error: %v", err)
	}
	var ae *APIError
	if !asAPIError(err, &ae) {
		t.Fatalf("expected APIError, got %T", err)
	}
	if ae.Body != "response body suppressed" {
		t.Fatalf("unexpected APIError body: %q", ae.Body)
	}
}

func asAPIError(err error, target **APIError) bool {
	ae, ok := err.(*APIError)
	if ok {
		*target = ae
	}
	return ok
}
