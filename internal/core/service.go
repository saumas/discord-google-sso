// Package core implements the business outcomes: verification (policy,
// epoch-checked 1:1 link reservation, pending-op persistence, role
// application), revocation (atomic epoch bump, link release, durable
// restoration operation), and reconciliation (membership sweeps and
// pending-op resumption). All state mutations funnel through the state
// store's compare-and-swap.
package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/saumas/discord-google-sso/internal/config"
	"github.com/saumas/discord-google-sso/internal/discordapi"
	"github.com/saumas/discord-google-sso/internal/session"
	"github.com/saumas/discord-google-sso/internal/state"
)

// RoleAPI is the Discord surface the core service needs.
type RoleAPI interface {
	GetMember(ctx context.Context, guildID, userID string) (discordapi.MemberInfo, error)
	AddRole(ctx context.Context, guildID, userID, roleID string) error
	RemoveRole(ctx context.Context, guildID, userID, roleID string) error
}

// VerifyStatus is the outcome of a verification attempt.
type VerifyStatus int

const (
	// VerifyVerified: link durable, roles applied, success may be shown.
	VerifyVerified VerifyStatus = iota
	// VerifyRejected: no link, no roles; reason is human-readable.
	VerifyRejected
	// VerifyPending: durable intent recorded (or transient provider
	// failure); completion is deferred and never claimed prematurely.
	VerifyPending
)

// VerifyInput carries everything established by the HTTP flow at reservation
// time.
type VerifyInput struct {
	MemberID    string
	Epoch       uint64    // revocation epoch captured at the Discord callback
	JoinedAt    time.Time // membership attestation observed then
	GoogleSub   string
	GoogleName  string
	GoogleEmail string
}

// VerifyResult reports the outcome.
type VerifyResult struct {
	Status VerifyStatus
	Reason string
}

// RevokeCommitResult reports what the atomic revocation commit did.
type RevokeCommitResult struct {
	Epoch            uint64
	CreatedRestoreOp bool
}

// Service owns business outcomes. Thin adapters (HTTP handlers, interaction
// handler, operator CLI) call it.
type Service struct {
	cfg      *config.Config
	store    *state.Store
	discord  RoleAPI
	sessions *session.Manager
	log      *slog.Logger
	locks    sync.Map // memberID -> *sync.Mutex
}

// New returns a Service.
func New(cfg *config.Config, store *state.Store, discord RoleAPI, sessions *session.Manager, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if sessions == nil {
		sessions = session.NewManager(cfg.SessionTTL)
	}
	return &Service{cfg: cfg, store: store, discord: discord, sessions: sessions, log: log}
}

var errReject = errors.New("rejected")

func newOpID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("core: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (s *Service) now() time.Time { return time.Now().UTC() }

// lockMember serializes Discord role mutations for one member within this
// process. The epoch/op-currency re-check is performed inside the critical
// section, so no window opens between check and call: a revocation's role
// restoration never interleaves with an in-flight grant for the same member,
// and the terminal Discord state always matches the newest durable intent.
func (s *Service) lockMember(id string) func() {
	v, _ := s.locks.LoadOrStore(id, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// Verify reserves the identity link (epoch-checked, 1:1 both directions),
// durably records the link and pending grant before any Discord side
// effect, applies roles, and reports completion only after the durable link
// and all required role changes have succeeded.
func (s *Service) Verify(ctx context.Context, in *VerifyInput) VerifyResult {
	opID := newOpID()
	guild := s.cfg.GuildID

	var reason string
	err := s.store.Update(ctx, guild, func(d *state.Doc) error {
		// Epoch check: a revocation (slash command or operator CLI) that
		// committed since the Discord callback invalidates this attempt.
		if d.Epoch(in.MemberID) != in.Epoch {
			reason = "Your verification session was invalidated (for example by a revocation). Please start again from the server invite link."
			return errReject
		}
		// 1:1 both directions.
		if existing := d.Members[in.MemberID]; existing != nil && existing.GoogleSub != in.GoogleSub {
			reason = "This Discord account is already verified with a different identity. Ask a server admin to revoke it first."
			return errReject
		}
		if other := d.FindMemberBySub(in.GoogleSub); other != "" && other != in.MemberID {
			reason = "This Google identity is already linked to another Discord account."
			return errReject
		}
		// Fold-in: a superseded, partially-applied revocation may have
		// re-added unverified roles; the new grant removes them again, so
		// restored unverified roles cannot survive the re-verification.
		removeRoles := append([]string(nil), s.cfg.RemoveRoles...)
		if op := d.Pending[in.MemberID]; op != nil && op.Kind == state.OpRevoke {
			removeRoles = state.UnionStrings(removeRoles, op.RestoredSoFar)
		}
		d.Members[in.MemberID] = &state.Member{
			GoogleSub:    in.GoogleSub,
			GoogleName:   in.GoogleName,
			GoogleEmail:  in.GoogleEmail,
			JoinedAt:     in.JoinedAt,
			AppliedRoles: nil,
		}
		// Replace any older outstanding operation: newest durable intent
		// determines the applied outcome.
		d.Pending[in.MemberID] = &state.PendingOp{
			Kind:           state.OpGrant,
			OpID:           opID,
			Epoch:          in.Epoch,
			AddRoles:       append([]string(nil), s.cfg.AddRoles...),
			RemoveRoles:    removeRoles,
			MemberJoinedAt: in.JoinedAt,
			CreatedAt:      s.now(),
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errReject) {
			return VerifyResult{Status: VerifyRejected, Reason: reason}
		}
		s.log.Error("verification reservation failed", "member", in.MemberID, "error", err.Error())
		return VerifyResult{Status: VerifyPending, Reason: "A temporary error occurred. Please try the verification link again."}
	}

	completed, err := s.applyGrantOp(ctx, in.MemberID, opID, in.Epoch)
	if err != nil {
		if errors.Is(err, errSuperseded) {
			return VerifyResult{Status: VerifyRejected, Reason: "Your verification was superseded. Please start again from the server invite link."}
		}
		// Role work is deferred: honest pending, never claimed as success.
		// The durable operation is resumed by reconciliation.
		s.log.Warn("grant role application deferred", "member", in.MemberID, "error", err.Error())
		return VerifyResult{Status: VerifyPending, Reason: "Verification is in progress. Your roles will be applied shortly; you can safely retry this link to re-check."}
	}
	if !completed {
		return VerifyResult{Status: VerifyPending, Reason: "Verification is in progress. Your roles will be applied shortly; you can safely retry this link to re-check."}
	}
	s.log.Info("member verified", "member", in.MemberID, "roles", len(s.cfg.AddRoles))
	return VerifyResult{Status: VerifyVerified}
}

var errSuperseded = errors.New("operation superseded")

// LoadDoc exposes the current state document to adapters (e.g. the epoch
// capture at the Discord callback).
func (s *Service) LoadDoc(ctx context.Context) (*state.Doc, error) {
	return s.store.Load(ctx, s.cfg.GuildID)
}

// currentOp loads the current document and the member's pending operation.
func (s *Service) currentOp(ctx context.Context, memberID string) (*state.Doc, *state.PendingOp, error) {
	doc, err := s.store.Load(ctx, s.cfg.GuildID)
	if err != nil {
		return nil, nil, err
	}
	return doc, doc.Pending[memberID], nil
}

// applyGrantOp applies a pending grant: each Discord side effect confirms
// the session's epoch is still current and the pending operation is still
// this one, aborting without success if superseded. Applied-role progress is
// persisted after each successful addition.
func (s *Service) applyGrantOp(ctx context.Context, memberID, opID string, epoch uint64) (bool, error) {
	unlock := s.lockMember(memberID)
	defer unlock()
	guild := s.cfg.GuildID

	for {
		doc, op, err := s.currentOp(ctx, memberID)
		if err != nil {
			return false, err
		}
		if op == nil || op.Kind != state.OpGrant || op.OpID != opID || doc.Epoch(memberID) != epoch {
			return false, errSuperseded
		}
		next := nextRole(op.AddRoles, op.AddedSoFar)
		if next == "" {
			break
		}
		if err := s.discord.AddRole(ctx, guild, memberID, next); err != nil {
			return false, roleFailure(s.log, "grant", memberID, next, err)
		}
		// Persist progress; removals are not progress (they are idempotent).
		if err := s.store.Update(ctx, guild, func(d *state.Doc) error {
			if cur := d.Pending[memberID]; cur != nil && cur.OpID == opID {
				cur.AddedSoFar = append(cur.AddedSoFar, next)
			}
			return nil
		}); err != nil {
			return false, err
		}
	}

	// Removals: idempotent, no progress tracking.
	_, op, err := s.currentOp(ctx, memberID)
	if err != nil {
		return false, err
	}
	if op == nil || op.Kind != state.OpGrant || op.OpID != opID {
		return false, errSuperseded
	}
	for _, role := range op.RemoveRoles {
		if err := s.discord.RemoveRole(ctx, guild, memberID, role); err != nil {
			return false, roleFailure(s.log, "grant", memberID, role, err)
		}
	}

	// Final confirmation before reporting success.
	var completed bool
	err = s.store.Update(ctx, guild, func(d *state.Doc) error {
		cur := d.Pending[memberID]
		if cur == nil || cur.OpID != opID || d.Epoch(memberID) != epoch {
			return nil // superseded between check and completion
		}
		if m := d.Members[memberID]; m != nil {
			m.AppliedRoles = append([]string(nil), cur.AddRoles...)
		}
		delete(d.Pending, memberID)
		completed = true
		return nil
	})
	if err != nil {
		return false, err
	}
	if !completed {
		return false, errSuperseded
	}
	return true, nil
}

func nextRole(all, done []string) string {
	doneSet := map[string]bool{}
	for _, r := range done {
		doneSet[r] = true
	}
	for _, r := range all {
		if !doneSet[r] {
			return r
		}
	}
	return ""
}

func roleFailure(log *slog.Logger, kind, member, role string, err error) error {
	if discordapi.IsPermanent(err) {
		// Permanent failures (role hierarchy, missing permission) are logged
		// distinctly: the operation stays durable and recoverable, but it
		// will not resolve by retrying.
		log.Error("role operation failed permanently", "kind", kind, "member", member, "role", role, "error", err.Error())
	}
	return err
}

// RevokeCommit performs the atomic revocation state commit: epoch bump,
// link release, and replacement of the member's pending grant with a
// durable revocation operation. It is shared by the slash-command entry
// point (in-process) and, via the state package, the operator CLI.
func (s *Service) RevokeCommit(ctx context.Context, memberID string) (*RevokeCommitResult, error) {
	opID := newOpID()
	var res RevokeCommitResult
	err := s.store.Update(ctx, s.cfg.GuildID, func(d *state.Doc) error {
		res.CreatedRestoreOp = d.ApplyRevokeCommit(memberID, opID, s.now())
		res.Epoch = d.Epochs[memberID]
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// Revoke is the full in-process revocation: commit, session
// invalidation, then role restoration (skipped for departed targets),
// retried by reconciliation until applied.
func (s *Service) Revoke(ctx context.Context, memberID string) (*RevokeCommitResult, error) {
	res, err := s.RevokeCommit(ctx, memberID)
	if err != nil {
		return nil, err
	}
	s.sessions.DropForMember(memberID)
	if res.CreatedRestoreOp {
		if _, err := s.applyRevokeOp(ctx, memberID); err != nil {
			// Restoration remains durable; reconciliation resumes it. The
			// outcome must not be reported as complete.
			return res, err
		}
	}
	return res, nil
}

// RevokeOutcome describes the completion state of a revocation's role work.
type RevokeOutcome int

const (
	RevokeRoleRestorationPending RevokeOutcome = iota
	RevokeCompleted
)

// applyRevokeOp applies a pending revocation operation: membership is
// evaluated when the role step executes; removals first, then the configured
// unverified-role additions resolved from current configuration.
func (s *Service) applyRevokeOp(ctx context.Context, memberID string) (RevokeOutcome, error) {
	unlock := s.lockMember(memberID)
	defer unlock()
	guild := s.cfg.GuildID

	_, op, err := s.currentOp(ctx, memberID)
	if err != nil {
		return RevokeRoleRestorationPending, err
	}
	if op == nil || op.Kind != state.OpRevoke {
		return RevokeCompleted, nil // superseded or already applied
	}

	// Membership is evaluated when the role step executes. API failures
	// never count as departure; the operation stays pending.
	info, err := s.discord.GetMember(ctx, guild, memberID)
	if err != nil {
		s.log.Warn("revoke membership lookup deferred", "member", memberID, "error", err.Error())
		return RevokeRoleRestorationPending, err
	}
	if info.NotFound {
		// A non-member holds no roles: complete with link release and
		// session invalidation already done by the commit.
		if err := s.store.Update(ctx, guild, func(d *state.Doc) error {
			if cur := d.Pending[memberID]; cur != nil && cur.Kind == state.OpRevoke && cur.OpID == op.OpID {
				delete(d.Pending, memberID)
			}
			return nil
		}); err != nil {
			return RevokeRoleRestorationPending, err
		}
		return RevokeCompleted, nil
	}

	for _, role := range op.RemoveRoles {
		if err := s.discord.RemoveRole(ctx, guild, memberID, role); err != nil {
			return RevokeRoleRestorationPending, roleFailure(s.log, "revoke", memberID, role, err)
		}
	}
	for _, role := range s.cfg.UnverifiedRoles {
		if err := s.discord.AddRole(ctx, guild, memberID, role); err != nil {
			return RevokeRoleRestorationPending, roleFailure(s.log, "revoke", memberID, role, err)
		}
		// Persist restoration progress: a newer grant superseding this
		// operation must remove the roles it re-added.
		if err := s.store.Update(ctx, guild, func(d *state.Doc) error {
			if cur := d.Pending[memberID]; cur != nil && cur.OpID == op.OpID && cur.Kind == state.OpRevoke {
				cur.RestoredSoFar = append(cur.RestoredSoFar, role)
			}
			return nil
		}); err != nil {
			return RevokeRoleRestorationPending, err
		}
	}
	if err := s.store.Update(ctx, guild, func(d *state.Doc) error {
		if cur := d.Pending[memberID]; cur != nil && cur.OpID == op.OpID && cur.Kind == state.OpRevoke {
			delete(d.Pending, memberID)
		}
		return nil
	}); err != nil {
		return RevokeRoleRestorationPending, err
	}
	return RevokeCompleted, nil
}

// Reconcile runs one membership sweep plus pending-op resumption. Confirmed
// departure (member lookup 404, or current joined_at strictly newer than
// the stored attestation, compared as parsed instants) releases the link and
// invalidates in-flight logins and pending operations. Provider outages,
// rate limits, and unavailable joined_at values never count as departure.
func (s *Service) Reconcile(ctx context.Context) {
	guild := s.cfg.GuildID
	doc, err := s.store.Load(ctx, guild)
	if err != nil {
		// Corrupt or foreign state: stop processing with a clear error
		// rather than resetting anything.
		s.log.Error("reconcile: state load failed; skipping cycle", "error", err.Error())
		return
	}

	for memberID, link := range doc.Members {
		info, err := s.discord.GetMember(ctx, guild, memberID)
		if err != nil {
			s.log.Warn("reconcile: member lookup failed; keeping member", "member", memberID, "error", err.Error())
			continue
		}
		if info.NotFound || info.JoinedAt.After(link.JoinedAt) {
			why := "left the server"
			if info.NotFound {
				why = "no longer a member"
			}
			s.log.Info("reconcile: releasing link after departure", "member", memberID, "reason", why)
			if err := s.store.Update(ctx, guild, func(d *state.Doc) error {
				if cur := d.Members[memberID]; cur != nil && cur.GoogleSub == link.GoogleSub {
					delete(d.Members, memberID)
					d.Epochs[memberID]++
					delete(d.Pending, memberID)
				}
				return nil
			}); err != nil {
				s.log.Error("reconcile: departure release write failed", "member", memberID, "error", err.Error())
				continue
			}
			s.sessions.DropForMember(memberID)
		}
	}

	// Pending-op resumption, covering every stored operation including
	// members whose link is already released (revocation operations).
	doc2, err := s.store.Load(ctx, guild)
	if err != nil {
		s.log.Error("reconcile: state reload failed; skipping resumption", "error", err.Error())
		return
	}
	for memberID, op := range doc2.Pending {
		switch op.Kind {
		case state.OpGrant:
			if doc2.Epoch(memberID) != op.Epoch {
				// Superseded by a revocation: discard the grant; the
				// revocation operation owns the terminal state.
				if err := s.store.Update(ctx, guild, func(d *state.Doc) error {
					if cur := d.Pending[memberID]; cur != nil && cur.OpID == op.OpID {
						delete(d.Pending, memberID)
					}
					return nil
				}); err != nil {
					s.log.Error("reconcile: stale grant discard failed", "member", memberID, "error", err.Error())
				}
				continue
			}
			// Resumed role work never relies on a stale membership
			// attestation: re-validate membership first.
			info, err := s.discord.GetMember(ctx, guild, memberID)
			if err != nil {
				s.log.Warn("reconcile: grant resumption lookup failed", "member", memberID, "error", err.Error())
				continue
			}
			if info.NotFound || info.JoinedAt.After(op.MemberJoinedAt) {
				s.log.Info("reconcile: discarding grant with stale membership attestation", "member", memberID)
				if err := s.store.Update(ctx, guild, func(d *state.Doc) error {
					if cur := d.Pending[memberID]; cur != nil && cur.OpID == op.OpID {
						delete(d.Pending, memberID)
					}
					if cur := d.Members[memberID]; cur != nil {
						delete(d.Members, memberID)
						d.Epochs[memberID]++
					}
					return nil
				}); err != nil {
					s.log.Error("reconcile: stale grant release failed", "member", memberID, "error", err.Error())
					continue
				}
				s.sessions.DropForMember(memberID)
				continue
			}
			if _, err := s.applyGrantOp(ctx, memberID, op.OpID, op.Epoch); err != nil {
				s.log.Warn("reconcile: grant resumption deferred", "member", memberID, "error", err.Error())
			}
		case state.OpRevoke:
			// Epoch-exempt: a newer epoch can only originate from another
			// revocation (same terminal state) or a newer verification
			// (which replaces the operation outright).
			if _, err := s.applyRevokeOp(ctx, memberID); err != nil {
				s.log.Warn("reconcile: revocation resumption deferred", "member", memberID, "error", err.Error())
			}
		}
	}
}

// RevokeCommitOnly performs just the atomic commit (used by the operator
// CLI entry point, which holds no Discord credentials and no role policy;
// role restoration is applied by the service's reconciler through the
// durable revocation operation).
func RevokeCommitOnly(ctx context.Context, store *state.Store, guildID, memberID string, log *slog.Logger) (*RevokeCommitResult, error) {
	opID := newOpID()
	var res RevokeCommitResult
	err := store.Update(ctx, guildID, func(d *state.Doc) error {
		res.CreatedRestoreOp = d.ApplyRevokeCommit(memberID, opID, time.Now().UTC())
		res.Epoch = d.Epochs[memberID]
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("revoke commit: %w", err)
	}
	return &res, nil
}
