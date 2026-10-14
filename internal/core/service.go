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
	MemberID  string
	Epoch     uint64    // revocation epoch captured at the Discord callback
	JoinedAt  time.Time // membership attestation observed then
	GoogleSub string
	// Policy inputs from the validated ID token: the workspace hd claim and
	// the email-verified flag. Verify enforces the organization policy
	// itself — the core service is the sole owner of business outcomes, so
	// no adapter can bypass the allowlist or the verified-email rule.
	Hd            string
	EmailVerified bool
	GoogleName    string
	GoogleEmail   string
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

// lockEntry is a reference-counted per-member mutex.
type lockEntry struct {
	mu   sync.Mutex
	refs int
}

// Service owns business outcomes. Thin adapters (HTTP handlers, interaction
// handler, operator CLI) call it.
type Service struct {
	cfg      *config.Config
	store    *state.Store
	discord  RoleAPI
	sessions *session.Manager
	log      *slog.Logger

	lockMu sync.Mutex
	locks  map[string]*lockEntry // memberID -> refcounted mutex
}

// New returns a Service.
func New(cfg *config.Config, store *state.Store, discord RoleAPI, sessions *session.Manager, log *slog.Logger) *Service {
	return &Service{cfg: cfg, store: store, discord: discord, sessions: sessions, log: log, locks: map[string]*lockEntry{}}
}

var errReject = errors.New("rejected")

var ErrSuperseded = errors.New("operation superseded")

func newOpID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("core: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (s *Service) now() time.Time { return time.Now().UTC() }

// domainAllowed reports whether the signed hd claim is in the configured
// Workspace domain allowlist (the single domain policy).
func (s *Service) domainAllowed(hd string) bool {
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

// lockMember serializes Discord role mutations for one member within this
// process. The epoch/op-currency re-check is performed inside the critical
// section, so no window opens between check and call: a revocation's role
// restoration never interleaves with an in-flight grant for the same member,
// and the terminal Discord state always matches the newest durable intent.
// Entries are reference-counted and evicted when the last holder unlocks,
// so the table stays bounded by members with in-flight role work.
func (s *Service) lockMember(id string) func() {
	s.lockMu.Lock()
	e := s.locks[id]
	if e == nil {
		e = &lockEntry{}
		s.locks[id] = e
	}
	e.refs++
	s.lockMu.Unlock()
	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		s.lockMu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(s.locks, id)
		}
		s.lockMu.Unlock()
	}
}

// Verify reserves the identity link (epoch-checked, 1:1 both directions),
// durably records the link and pending grant before any Discord side
// effect, applies roles, and reports completion only after the durable link
// and all required role changes have succeeded.
func (s *Service) Verify(ctx context.Context, in *VerifyInput) VerifyResult {
	// Organization policy: verified email plus an allowed signed Workspace
	// hd claim — the single domain check.
	if !in.EmailVerified {
		s.log.Info("verification rejected", "member", in.MemberID, "reason", "unverified-email")
		return VerifyResult{Status: VerifyRejected, Reason: "The Google account's email address is not verified."}
	}
	if !s.domainAllowed(in.Hd) {
		s.log.Info("verification rejected", "member", in.MemberID, "reason", "domain-not-allowed")
		return VerifyResult{Status: VerifyRejected, Reason: "This server only accepts members with an approved organization Google account."}
	}

	opID := newOpID()
	guild := s.cfg.GuildID

	var reason string
	// Serialize with in-flight role work for this member: taking the member
	// lock around the reservation means a role call can never be in flight
	// when the superseding commit lands (and vice versa), so every side
	// effect is either fully recorded in its operation or the operation was
	// already replaced before the call was issued.
	unlockReservation := s.lockMember(in.MemberID)
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
		// Retained applied-role history: roles actually added at grant time
		// survive re-assertion, so a configuration change between grant and
		// revoke never leaves stale granted roles behind.
		var prevApplied []string
		if existing := d.Members[in.MemberID]; existing != nil && existing.GoogleSub == in.GoogleSub {
			prevApplied = existing.AppliedRoles
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
			AppliedRoles: append([]string(nil), prevApplied...),
		}
		// Replace any older outstanding operation: newest durable intent
		// determines the applied outcome. Additions carry the configured set
		// plus the retained history, so a later revocation removes every
		// role verification ever granted this member.
		d.Pending[in.MemberID] = &state.PendingOp{
			Kind:           state.OpGrant,
			OpID:           opID,
			Epoch:          in.Epoch,
			AddRoles:       state.UnionStrings(s.cfg.AddRoles, prevApplied),
			RemoveRoles:    removeRoles,
			MemberJoinedAt: in.JoinedAt,
			CreatedAt:      s.now(),
		}
		return nil
	})
	// Release the member lock before role application: applyGrantOp takes
	// the same (non-reentrant) lock, and the reservation hold must end with
	// the CAS either way.
	unlockReservation()
	if err != nil {
		if errors.Is(err, errReject) {
			s.log.Info("verification rejected", "member", in.MemberID, "reason", reason)
			return VerifyResult{Status: VerifyRejected, Reason: reason}
		}
		s.log.Error("verification reservation failed", "member", in.MemberID, "error", err.Error())
		return VerifyResult{Status: VerifyPending, Reason: "A temporary error occurred. Please try the verification link again."}
	}

	completed, err := s.applyGrantOp(ctx, in.MemberID, opID, in.Epoch)
	if err != nil {
		if errors.Is(err, ErrSuperseded) {
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

// updateOp applies a guarded pending-op mutation under the store's CAS: the
// mutation only runs when the member's pending operation still has the
// expected OpID and kind. A guard mismatch returns ErrSuperseded instead of
// silently no-oping, so in-flight role loops abort when a newer durable
// intent has replaced the operation.
func (s *Service) updateOp(ctx context.Context, memberID, opID string, require state.OpKind, apply func(d *state.Doc, cur *state.PendingOp)) error {
	return s.store.Update(ctx, s.cfg.GuildID, func(d *state.Doc) error {
		cur := d.Pending[memberID]
		if cur == nil || cur.OpID != opID || cur.Kind != require {
			return ErrSuperseded
		}
		apply(d, cur)
		return nil
	})
}

// opCurrent returns ErrSuperseded unless the member's pending operation is
// still the given one. Run inside the per-member critical section before
// every Discord side effect, so no role call lands after a superseding
// reservation has replaced the operation.
func (s *Service) opCurrent(ctx context.Context, memberID, opID string, require state.OpKind) error {
	_, cur, err := s.currentOp(ctx, memberID)
	if err != nil {
		return err
	}
	if cur == nil || cur.OpID != opID || cur.Kind != require {
		return ErrSuperseded
	}
	return nil
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
			return false, ErrSuperseded
		}
		next := nextRole(op.AddRoles, op.AddedSoFar)
		if next == "" {
			break
		}
		if err := s.discord.AddRole(ctx, guild, memberID, next); err != nil {
			return false, roleFailure(s.log, "grant", memberID, next, err)
		}
		// Persist progress; removals are not progress (they are idempotent).
		if err := s.updateOp(ctx, memberID, opID, state.OpGrant, func(_ *state.Doc, cur *state.PendingOp) {
			cur.AddedSoFar = append(cur.AddedSoFar, next)
		}); err != nil {
			return false, err
		}
	}

	// Removals: idempotent, no progress tracking, but still currency-checked
	// before each call so a superseding operation owns the terminal state.
	{
		_, op, err := s.currentOp(ctx, memberID)
		if err != nil {
			return false, err
		}
		if op == nil || op.Kind != state.OpGrant || op.OpID != opID {
			return false, ErrSuperseded
		}
		for _, role := range op.RemoveRoles {
			if err := s.opCurrent(ctx, memberID, opID, state.OpGrant); err != nil {
				return false, err
			}
			if err := s.discord.RemoveRole(ctx, guild, memberID, role); err != nil {
				return false, roleFailure(s.log, "grant", memberID, role, err)
			}
		}
	}

	// Final confirmation before reporting success. `completed` is reset on
	// every CAS attempt: if the first write loses the race to a superseding
	// commit, the retried mutation must not inherit the earlier attempt's
	// verdict.
	var completed bool
	err := s.store.Update(ctx, guild, func(d *state.Doc) error {
		completed = false
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
		return false, ErrSuperseded
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

// commitRevoke is the single owner of the atomic revocation commit envelope:
// new OpID, one store.Update carrying state.Doc.ApplyRevokeCommit, and the
// resulting commit report. Both revocation entry points (the slash-command
// path and the operator CLI) funnel through it so they cannot drift.
func commitRevoke(ctx context.Context, store *state.Store, guildID, memberID string, now time.Time) (*RevokeCommitResult, error) {
	opID := newOpID()
	var res RevokeCommitResult
	err := store.Update(ctx, guildID, func(d *state.Doc) error {
		res.CreatedRestoreOp = d.ApplyRevokeCommit(memberID, opID, now)
		res.Epoch = d.Epochs[memberID]
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("revoke commit: %w", err)
	}
	return &res, nil
}

// RevokeCommit performs the atomic revocation state commit: epoch bump,
// link release, and replacement of the member's pending grant with a
// durable revocation operation.
func (s *Service) RevokeCommit(ctx context.Context, memberID string) (*RevokeCommitResult, error) {
	// Serialize with in-flight role work for this member (see Verify).
	unlock := s.lockMember(memberID)
	defer unlock()
	return commitRevoke(ctx, s.store, s.cfg.GuildID, memberID, s.now())
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
		if err := s.applyRevokeOp(ctx, memberID); err != nil {
			// Restoration remains durable; reconciliation resumes it. The
			// outcome must not be reported as complete.
			return res, err
		}
	}
	return res, nil
}

// applyRevokeOp applies a pending revocation operation: membership is
// evaluated when the role step executes; removals first, then the configured
// unverified-role additions resolved from current configuration. Every
// Discord side effect is preceded by an op-currency re-check (mirroring
// applyGrantOp), so a restoration whose operation has been superseded by a
// newer verification stops before further role calls — the newest durable
// intent owns the terminal state.
func (s *Service) applyRevokeOp(ctx context.Context, memberID string) error {
	unlock := s.lockMember(memberID)
	defer unlock()
	guild := s.cfg.GuildID

	_, op, err := s.currentOp(ctx, memberID)
	if err != nil {
		return err
	}
	if op == nil {
		return nil // genuinely already applied
	}
	if op.Kind != state.OpRevoke {
		// The revocation operation was replaced (e.g. by a re-verification
		// reservation landing between the commit and this role step): report
		// supersession so callers never claim restoration completed.
		return ErrSuperseded
	}

	// Membership is evaluated when the role step executes. API failures
	// never count as departure; the operation stays pending.
	info, err := s.discord.GetMember(ctx, guild, memberID)
	if err != nil {
		s.log.Warn("revoke membership lookup deferred", "member", memberID, "error", err.Error())
		return err
	}
	if info.NotFound {
		// A non-member holds no roles: complete with link release and
		// session invalidation already done by the commit.
		return s.updateOp(ctx, memberID, op.OpID, state.OpRevoke, func(d *state.Doc, _ *state.PendingOp) {
			delete(d.Pending, memberID)
		})
	}

	for _, role := range op.RemoveRoles {
		if err := s.opCurrent(ctx, memberID, op.OpID, state.OpRevoke); err != nil {
			return err
		}
		if err := s.discord.RemoveRole(ctx, guild, memberID, role); err != nil {
			return roleFailure(s.log, "revoke", memberID, role, err)
		}
	}
	for _, role := range s.cfg.UnverifiedRoles {
		if err := s.opCurrent(ctx, memberID, op.OpID, state.OpRevoke); err != nil {
			return err
		}
		if err := s.discord.AddRole(ctx, guild, memberID, role); err != nil {
			return roleFailure(s.log, "revoke", memberID, role, err)
		}
		// Persist restoration progress: a newer grant superseding this
		// operation must remove the roles it re-added. A guard mismatch
		// aborts the loop instead of silently dropping the record.
		if err := s.updateOp(ctx, memberID, op.OpID, state.OpRevoke, func(_ *state.Doc, cur *state.PendingOp) {
			cur.RestoredSoFar = append(cur.RestoredSoFar, role)
		}); err != nil {
			return err
		}
	}
	return s.updateOp(ctx, memberID, op.OpID, state.OpRevoke, func(d *state.Doc, _ *state.PendingOp) {
		delete(d.Pending, memberID)
	})
}

// Reconcile runs one membership sweep plus pending-op resumption. Confirmed
// departure (member lookup 404, or current joined_at strictly newer than
// the stored attestation, compared as parsed instants) releases the link and
// invalidates in-flight logins and pending operations. Provider outages,
// rate limits, and unavailable joined_at values never count as departure.
// Release writes are guarded on the attestation they were decided from, so
// a link refreshed by a concurrent re-verification is never released by a
// stale departure observation.
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
			released := false
			// Serialize with in-flight role work for this member (same
			// discipline as Verify/RevokeCommit): the release cannot commit
			// between a grant's currency check and its Discord call, so no
			// role lands after the release without a durable record.
			unlock := s.lockMember(memberID)
			err := s.store.Update(ctx, guild, func(d *state.Doc) error {
				released = d.ApplyDepartureRelease(memberID, link.JoinedAt)
				return nil
			})
			unlock()
			if err != nil {
				s.log.Error("reconcile: departure release write failed", "member", memberID, "error", err.Error())
				continue
			}
			if released {
				s.sessions.DropForMember(memberID)
			}
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
				if err := s.updateOp(ctx, memberID, op.OpID, state.OpGrant, func(d *state.Doc, _ *state.PendingOp) {
					delete(d.Pending, memberID)
				}); err != nil && !errors.Is(err, ErrSuperseded) {
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
				released := false
				// Serialize with in-flight role work (see the sweep branch).
				unlock := s.lockMember(memberID)
				err := s.store.Update(ctx, guild, func(d *state.Doc) error {
					if cur := d.Pending[memberID]; cur != nil && cur.OpID == op.OpID {
						delete(d.Pending, memberID)
					}
					released = d.ApplyDepartureRelease(memberID, op.MemberJoinedAt)
					return nil
				})
				unlock()
				if err != nil {
					s.log.Error("reconcile: stale grant release failed", "member", memberID, "error", err.Error())
					continue
				}
				if released {
					s.sessions.DropForMember(memberID)
				}
				continue
			}
			if info.JoinedAt.IsZero() {
				// Unusable joined_at: the membership-freshness comparison is
				// indeterminate, and a grant is an access-extending
				// operation — defer to a later cycle instead of applying.
				s.log.Warn("reconcile: grant resumption deferred (no usable joined_at)", "member", memberID)
				continue
			}
			if _, err := s.applyGrantOp(ctx, memberID, op.OpID, op.Epoch); err != nil {
				s.log.Warn("reconcile: grant resumption deferred", "member", memberID, "error", err.Error())
			}
		case state.OpRevoke:
			// Epoch-exempt: a newer epoch can only originate from another
			// revocation (same terminal state) or a newer verification
			// (which replaces the operation outright).
			if err := s.applyRevokeOp(ctx, memberID); err != nil {
				s.log.Warn("reconcile: revocation resumption deferred", "member", memberID, "error", err.Error())
			}
		}
	}
}

// RevokeCommitOnly performs just the atomic commit (used by the operator
// CLI entry point, which holds no Discord credentials and no role policy;
// role restoration is applied by the service's reconciler through the
// durable revocation operation). It shares commitRevoke with the server's
// in-process path, so both revocation entry points have identical semantics.
func RevokeCommitOnly(ctx context.Context, store *state.Store, guildID, memberID string) (*RevokeCommitResult, error) {
	return commitRevoke(ctx, store, guildID, memberID, time.Now().UTC())
}
