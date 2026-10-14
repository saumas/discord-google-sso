// Package session implements the in-memory, short-lived verification session
// manager. Sessions hold OAuth state and nonce; callback consumption is
// single-use. With one replica this is adequate; a restart drops sessions
// and members get a fresh-login path.
package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Errors surfaced to the flow layer.
var (
	ErrUnknownState = errors.New("unknown or expired session state")
	ErrWrongStage   = errors.New("session state not valid for this stage")
)

// Stage tracks how far a verification session has progressed.
type Stage int

const (
	// StageDiscord awaits the Discord callback (identified by DiscordState).
	StageDiscord Stage = iota
	// StageGoogle awaits the Google callback (identified by GoogleState).
	StageGoogle
)

// Session is one member's in-flight verification.
type Session struct {
	DiscordState string
	GoogleState  string
	Nonce        string
	CreatedAt    time.Time
	ExpiresAt    time.Time

	// Set once the Discord identity is established at the Discord callback.
	Stage    Stage
	MemberID string
	// Epoch is the revocation epoch captured at the Discord callback. The
	// link reservation must observe it still current.
	Epoch uint64
	// JoinedAt is the membership attestation observed at the Discord
	// callback.
	JoinedAt time.Time
}

func newToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("session: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Manager tracks active sessions.
type Manager struct {
	mu   sync.Mutex
	byID map[string]*Session
	ttl  time.Duration
	now  func() time.Time
}

// NewManager returns a Manager with the given session TTL.
func NewManager(ttl time.Duration) *Manager {
	return &Manager{byID: map[string]*Session{}, ttl: ttl, now: time.Now}
}

// Start creates a fresh session and returns it. It first sweeps expired
// entries, so abandoned sessions (whose tokens are never presented again)
// are reclaimed and memory stays bounded by one TTL window of traffic.
func (m *Manager) Start() *Session {
	now := m.now()
	m.mu.Lock()
	for k, s := range m.byID {
		if now.After(s.ExpiresAt) {
			delete(m.byID, k)
		}
	}
	s := &Session{
		DiscordState: newToken(),
		CreatedAt:    now,
	}
	s.ExpiresAt = s.CreatedAt.Add(m.ttl)
	m.byID[s.DiscordState] = s
	m.mu.Unlock()
	return s
}

// Consume validates and consumes the state token for the given stage. On
// success for the Discord stage the session rotates to the Google stage
// (generating the Google state and nonce); a Google-stage consume destroys
// the session, making callbacks single-use.
func (m *Manager) Consume(state string, stage Stage) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[state]
	if !ok || m.now().After(s.ExpiresAt) {
		if ok {
			delete(m.byID, state)
		}
		return nil, ErrUnknownState
	}
	if s.Stage != stage {
		return nil, ErrWrongStage
	}
	switch stage {
	case StageDiscord:
		s.GoogleState = newToken()
		s.Nonce = newToken()
		s.Stage = StageGoogle
		m.byID[s.GoogleState] = s
		return s, nil
	case StageGoogle:
		delete(m.byID, s.DiscordState)
		delete(m.byID, s.GoogleState)
		return s, nil
	}
	return nil, ErrWrongStage
}

// DropForMember invalidates all pending login sessions bound to a Discord
// member (used by in-process revocation).
func (m *Manager) DropForMember(memberID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.byID {
		if s.MemberID == memberID {
			delete(m.byID, s.DiscordState)
			delete(m.byID, s.GoogleState)
			n++
		}
	}
	return n
}

// SetMember binds the Discord identity to a session at the Discord callback.
func (m *Manager) SetMember(state string, memberID string, epoch uint64, joinedAt time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.byID[state]; ok {
		s.MemberID = memberID
		s.Epoch = epoch
		s.JoinedAt = joinedAt
	}
}
