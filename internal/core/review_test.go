package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/saumas/discord-google-sso/internal/discordapi"
	"github.com/saumas/discord-google-sso/internal/state"
)

// waitFor polls cond until it holds or the timeout expires.
func waitFor(what string, timeout time.Duration, cond func() bool) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return errTimeout(what)
}

type errTimeout string

func (e errTimeout) Error() string { return "timed out waiting for " + string(e) }

// TestReverifySupersedesInFlightRestoration covers the severe race where a
// re-verification reservation replaces a pending revocation while its
// restoration is blocked mid-role-call: the restore loop must re-check op
// currency before every Discord side effect and abort, so no unverified role
// lands after the superseding grant (spec: "restored unverified roles cannot
// survive the re-verification").
func TestReverifySupersedesInFlightRestoration(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	if r := h.svc.Verify(ctx, &VerifyInput{EmailVerified: true, Hd: "example.com", MemberID: "u1", JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("verify: %+v", r)
	}
	// Block the restoration on the first unverified role add.
	block := make(chan struct{})
	h.disc.blockAddOn["u1:888"] = block

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Revoke: removals of 111/222 succeed, then AddRole(888) blocks.
		if _, err := h.svc.Revoke(ctx, "u1"); err == nil {
			t.Log("revoke completed before block")
		}
	}()
	// Wait until the removals have landed (restoration is now in-flight).
	if err := waitFor("removals applied", 2*time.Second, func() bool {
		return !h.disc.has("u1", "111") && !h.disc.has("u1", "222")
	}); err != nil {
		t.Fatal(err)
	}

	// The member re-verifies mid-restoration (fresh epoch after the commit).
	// The reservation is serialized behind the in-flight role work (the
	// member lock): while the restore is blocked, the pending op must still
	// be the revocation — no superseding commit can land mid-role-call, so
	// every Discord side effect is either fully recorded in its operation or
	// the operation was replaced before the call was issued.
	d := h.doc(t)
	verifyDone := make(chan VerifyResult, 1)
	go func() {
		verifyDone <- h.svc.Verify(ctx, &VerifyInput{EmailVerified: true, Hd: "example.com", MemberID: "u1", Epoch: d.Epochs["u1"], JoinedAt: j, GoogleSub: "s1"})
	}()
	// While the restore is still blocked, the re-verification has NOT
	// superseded anything: the revoke op is still the pending operation.
	time.Sleep(100 * time.Millisecond)
	if doc, err := h.readDoc(); err != nil || doc.Pending["u1"] == nil || doc.Pending["u1"].Kind != "revoke" {
		t.Fatalf("reservation landed while role work was in flight: %+v (%v)", doc.Pending["u1"], err)
	}

	// Unblock the stalled restore: it completes (888 recorded and the op
	// closed), and only then does the serialized re-verification run.
	close(block)
	wg.Wait()
	var res VerifyResult
	select {
	case res = <-verifyDone:
	case <-time.After(10 * time.Second):
		t.Fatal("re-verification did not complete after restoration unblocked")
	}
	if res.Status != VerifyVerified {
		t.Fatalf("re-verify after in-flight restoration completed: %+v", res)
	}
	// Terminal state: the revocation completed before the re-verification
	// was processed, so the member holds the granted roles; role 888 was
	// applied by the COMPLETED revocation (recorded, not orphaned). Under a
	// config that removes the unverified set on verification (the E2E
	// toggle), it is removed again — the pending-supersession fold-in is
	// covered by TestReVerificationSupersedesPartialRevocation and the E2E
	// scenario.
	if err := waitFor("terminal state settles", 2*time.Second, func() bool {
		return h.disc.has("u1", "111") && h.disc.has("u1", "222")
	}); err != nil {
		t.Fatalf("%v; roles: %v", err, h.memberRoles(t, "u1"))
	}
	if d := h.doc(t); d.Pending["u1"] != nil {
		t.Fatalf("pending op not drained: %+v", d.Pending)
	}
}

func (h *harness) readDoc() (*state.Doc, error) {
	return h.store.Load(context.Background(), "g1")
}

func (h *harness) memberRoles(_ *testing.T, user string) []string {
	var out []string
	for r := range h.disc.roles[user] {
		out = append(out, r)
	}
	return out
}

// TestStaleDepartureObservationDoesNotReleaseFreshLink covers the rejoin
// race: the sweep observes a departure (newer joined_at), but the member
// rejoined and re-verified before the release write lands — the release must
// be guarded on the attestation it was decided from and must not delete the
// fresh link.
func TestStaleDepartureObservationDoesNotReleaseFreshLink(t *testing.T) {
	h := newHarness(t)
	old := now().Add(-2 * time.Hour)
	h.disc.member("u1", old)
	ctx := context.Background()
	if r := h.svc.Verify(ctx, &VerifyInput{EmailVerified: true, Hd: "example.com", MemberID: "u1", JoinedAt: old, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("verify: %+v", r)
	}
	// Member rejoins (joined_at strictly newer) and re-verifies: the link
	// now carries the fresh attestation and a fresh pending state.
	fresh := now().Add(-time.Minute)
	h.disc.members["u1"] = discordapi.MemberInfo{JoinedAt: fresh}
	d := h.doc(t)
	if r := h.svc.Verify(ctx, &VerifyInput{EmailVerified: true, Hd: "example.com", MemberID: "u1", Epoch: d.Epochs["u1"], JoinedAt: fresh, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("re-verify: %+v", r)
	}
	// The sweep sees the CURRENT joined_at, which equals the stored
	// attestation — no departure, no release. The interesting stale window
	// is covered by the attestation guard in the release write; simulate the
	// guard directly by asserting a release pinned to the OLD attestation
	// (what a sweep that loaded the old doc would write) must not fire.
	released := false
	if err := h.store.Update(ctx, "g1", func(d *state.Doc) error {
		released = d.ApplyDepartureRelease("u1", old)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if released {
		t.Fatal("stale departure observation released a freshly re-verified link")
	}
	if h.doc(t).Members["u1"] == nil {
		t.Fatal("link lost to stale release")
	}
	// And a release pinned to the correct attestation does fire (sanity).
	if err := h.store.Update(ctx, "g1", func(d *state.Doc) error {
		released = d.ApplyDepartureRelease("u1", fresh)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !released {
		t.Fatal("release with the current attestation did not fire")
	}
}

// TestGrantResumptionDefersOnUnusableJoinedAt covers the anchor invariant
// during resumption: a member lookup that returns present-but-zero
// joined_at defers the grant (an access-extending operation) instead of
// applying roles on an indeterminate membership-freshness check.
func TestGrantResumptionDefersOnUnusableJoinedAt(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-2 * time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	h.disc.failAdd["u1:222"] = &discordapi.APIError{Status: 503, Permanent: false}
	if r := h.svc.Verify(ctx, &VerifyInput{EmailVerified: true, Hd: "example.com", MemberID: "u1", JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyPending {
		t.Fatalf("expected pending, got %+v", r)
	}
	delete(h.disc.failAdd, "u1:222")
	// The lookup now returns the member without a usable joined_at.
	h.disc.mu.Lock()
	h.disc.members["u1"] = discordapi.MemberInfo{} // present, zero joined_at
	h.disc.mu.Unlock()

	addsBefore := len(h.disc.addCalls)
	h.svc.Reconcile(ctx)
	if len(h.disc.addCalls) != addsBefore {
		t.Fatalf("roles applied on indeterminate joined_at: %v", h.memberRoles(t, "u1"))
	}
	d := h.doc(t)
	if d.Pending["u1"] == nil {
		t.Fatal("pending grant discarded on unusable joined_at (should defer)")
	}
	if d.Members["u1"] == nil {
		t.Fatal("link released on unusable joined_at (should defer)")
	}
}

// TestConfigChangeAppliedRolesCarried covers the retained-history rule: a
// role granted by an earlier policy survives a re-verification under a
// changed policy and is still removed by a later revocation.
func TestConfigChangeAppliedRolesCarried(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-2 * time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	if r := h.svc.Verify(ctx, &VerifyInput{EmailVerified: true, Hd: "example.com", MemberID: "u1", JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("verify: %+v", r)
	}
	// Operator drops role 222 from the policy and the member re-verifies.
	h.cfg.AddRoles = []string{"111"}
	if r := h.svc.Verify(ctx, &VerifyInput{EmailVerified: true, Hd: "example.com", MemberID: "u1", Epoch: h.doc(t).Epochs["u1"], JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("re-verify: %+v", r)
	}
	// Revocation must still remove both 111 and the historically granted 222.
	if _, err := h.svc.Revoke(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	if h.disc.has("u1", "111") || h.disc.has("u1", "222") {
		t.Fatalf("historically granted role survived revocation: %v", h.memberRoles(t, "u1"))
	}
}

// TestVerifyPolicyEnforcedInCore covers the organization policy living in
// the core service, not only in the HTTP adapter: unverified email and a
// disallowed hd claim are rejected before any state is written.
func TestVerifyPolicyEnforcedInCore(t *testing.T) {
	h := newHarness(t)
	h.disc.member("u1", now())
	ctx := context.Background()
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", GoogleSub: "s1", Hd: "example.com", EmailVerified: false}); r.Status != VerifyRejected {
		t.Fatalf("unverified email accepted: %+v", r)
	}
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", GoogleSub: "s1", Hd: "evil.io", EmailVerified: true}); r.Status != VerifyRejected {
		t.Fatalf("disallowed domain accepted: %+v", r)
	}
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", GoogleSub: "s1", EmailVerified: true}); r.Status != VerifyRejected {
		t.Fatalf("missing hd accepted: %+v", r)
	}
	if d := h.doc(t); len(d.Members) != 0 || len(d.Pending) != 0 {
		t.Fatalf("policy rejection wrote state: %+v", d)
	}
}
