package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/saumas/discord-google-sso/internal/discordapi"
)

// TestDepartureReleaseSerializedWithInFlightGrant covers the interleaving
// where a membership sweep decides a departure (member left and rejoined
// with a newer joined_at) while a grant's role call is in flight: the
// release write takes the member lock, so it cannot commit between the
// grant's currency check and its Discord call. The grant either completes
// durably first (and the release then cleans up the stale link) or aborts at
// its entry check — it never reports supersession after applying roles with
// no durable record.
func TestDepartureReleaseSerializedWithInFlightGrant(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-2 * time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()

	// Block the grant's first role add.
	block := make(chan struct{})
	h.disc.blockAddOn["u1:111"] = block

	verifyDone := make(chan VerifyResult, 1)
	go func() {
		verifyDone <- h.svc.Verify(ctx, &VerifyInput{EmailVerified: true, Hd: "example.com", MemberID: "u1", JoinedAt: j, GoogleSub: "s1"})
	}()
	// Wait until the grant is inside AddRole(111), holding the member lock.
	time.Sleep(100 * time.Millisecond)

	// The member left and rejoined; the sweep decides departure and blocks
	// on the member lock at the release write.
	rejoined := now().Add(-time.Minute)
	h.disc.mu.Lock()
	h.disc.members["u1"] = discordapi.MemberInfo{JoinedAt: rejoined}
	h.disc.mu.Unlock()
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		h.svc.Reconcile(ctx)
	}()
	time.Sleep(100 * time.Millisecond)

	// Unblock the grant: it completes while holding the lock (its currency
	// checks still pass — the release has not committed), then the release
	// fires and removes the stale link.
	close(block)
	var res VerifyResult
	select {
	case res = <-verifyDone:
	case <-time.After(10 * time.Second):
		t.Fatal("verify did not complete")
	}
	select {
	case <-sweepDone:
	case <-time.After(10 * time.Second):
		t.Fatal("sweep did not complete")
	}

	// With serialization, the grant completed durably before the release was
	// decided (the pre-fix race reported supersession while the in-flight
	// role had already landed, leaving an unrecorded granted role).
	if res.Status != VerifyVerified {
		t.Fatalf("serialized grant should complete: %+v", res)
	}
	d := h.doc(t)
	if d.Members["u1"] != nil {
		t.Fatalf("stale link not released after departure: %+v", d.Members)
	}
	if d.Pending["u1"] != nil {
		t.Fatalf("pending op not cleared: %+v", d.Pending)
	}
	if d.Epochs["u1"] == 0 {
		t.Fatal("release did not bump the epoch")
	}
}

// TestApplyRevokeOpReportsPreRoleStepSupersession covers the entry check:
// when a re-verification reservation replaces the revocation operation
// before its role step begins, applyRevokeOp must report ErrSuperseded (not
// nil) so the caller never claims restoration completed.
func TestApplyRevokeOpReportsPreRoleStepSupersession(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-2 * time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	if r := h.svc.Verify(ctx, &VerifyInput{EmailVerified: true, Hd: "example.com", MemberID: "u1", JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("verify: %+v", r)
	}
	// The revocation commits...
	if _, err := h.svc.RevokeCommit(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	// ...and a re-verification replaces the revocation operation before
	// its role step begins. The re-verification's grant stays pending (a
	// transient role failure) so the pending map holds a grant op at the
	// stale revocation's entry check.
	h.disc.failAdd["u1:222"] = &discordapi.APIError{Status: 503, Permanent: false}
	d := h.doc(t)
	if r := h.svc.Verify(ctx, &VerifyInput{EmailVerified: true, Hd: "example.com", MemberID: "u1", Epoch: d.Epochs["u1"], JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyPending {
		t.Fatalf("re-verify (expected pending grant): %+v", r)
	}
	delete(h.disc.failAdd, "u1:222")
	// The stale revocation's role step must report supersession, not
	// completion.
	if err := h.svc.applyRevokeOp(ctx, "u1"); !errors.Is(err, ErrSuperseded) {
		t.Fatalf("expected ErrSuperseded, got %v", err)
	}
	// The genuinely-already-applied case still reports nil: complete a
	// revocation and re-run its role step.
	if _, err := h.svc.Revoke(ctx, "u1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := h.svc.applyRevokeOp(ctx, "u1"); err != nil {
		t.Fatalf("expected nil for already-applied revocation, got %v", err)
	}
}
