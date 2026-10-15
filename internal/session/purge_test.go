package session

import (
	"testing"
	"time"
)

// TestStartPurgesExpired covers the reaper: abandoned sessions (whose state
// tokens are never presented again) are reclaimed by later Start calls, so
// the map stays bounded by one TTL window of traffic.
func TestStartPurgesExpired(t *testing.T) {
	m := NewManager(10 * time.Millisecond)
	abandoned := m.Start()

	time.Sleep(20 * time.Millisecond) // abandoned is now expired

	// A session created after the sleep is still live; its Start call
	// reaped the expired abandoned entry.
	inFlight := m.Start()
	m.mu.Lock()
	if n := len(m.byID); n != 1 {
		t.Fatalf("expected abandoned session reaped (1 live), got %d", n)
	}
	m.mu.Unlock()

	m.Start()
	m.mu.Lock()
	n := len(m.byID)
	m.mu.Unlock()
	if n != 2 { // inFlight + the session started above
		t.Fatalf("expected 2 live sessions, got %d", n)
	}
	if _, err := m.Consume(abandoned.DiscordState, StageDiscord); err == nil {
		t.Fatal("expired session accepted after purge")
	}
	if _, err := m.Consume(inFlight.DiscordState, StageDiscord); err != nil {
		t.Fatalf("live session lost: %v", err)
	}
}
