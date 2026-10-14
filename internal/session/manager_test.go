package session

import (
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	m := NewManager(time.Minute)
	s := m.Start()

	// Discord leg consumes and rotates.
	s2, err := m.Consume(s.DiscordState, StageDiscord)
	if err != nil || s2 != s {
		t.Fatalf("discord consume: %v", err)
	}
	if s.Stage != StageGoogle || s.GoogleState == "" || s.Nonce == "" {
		t.Fatalf("rotation incomplete: %+v", s)
	}
	// Discord state is single-use: replay fails.
	if _, err := m.Consume(s.DiscordState, StageDiscord); err == nil {
		t.Fatal("discord state replay accepted")
	}
	// Google leg consumes and destroys.
	if _, err := m.Consume(s.GoogleState, StageGoogle); err != nil {
		t.Fatalf("google consume: %v", err)
	}
	if _, err := m.Consume(s.GoogleState, StageGoogle); err == nil {
		t.Fatal("google state replay accepted")
	}
}

func TestSessionExpiry(t *testing.T) {
	m := NewManager(time.Millisecond)
	s := m.Start()
	time.Sleep(5 * time.Millisecond)
	if _, err := m.Consume(s.DiscordState, StageDiscord); err == nil {
		t.Fatal("expired session accepted")
	}
}

func TestDropForMember(t *testing.T) {
	m := NewManager(time.Minute)
	s := m.Start()
	m.SetMember(s.DiscordState, "u1", 3, time.Now())
	if n := m.DropForMember("u1"); n != 1 {
		t.Fatalf("dropped %d, want 1", n)
	}
	if _, err := m.Consume(s.DiscordState, StageDiscord); err == nil {
		t.Fatal("dropped session still usable")
	}
}

func TestWrongStage(t *testing.T) {
	m := NewManager(time.Minute)
	s := m.Start()
	if _, err := m.Consume(s.DiscordState, StageGoogle); err == nil {
		t.Fatal("wrong stage accepted")
	}
}
