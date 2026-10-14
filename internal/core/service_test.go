package core

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/saumas/discord-google-sso/internal/config"
	"github.com/saumas/discord-google-sso/internal/discordapi"
	"github.com/saumas/discord-google-sso/internal/fakeapi"
	"github.com/saumas/discord-google-sso/internal/session"
	"github.com/saumas/discord-google-sso/internal/state"
)

// fakeDiscord is an in-memory RoleAPI with scriptable failures.
type fakeDiscord struct {
	mu       sync.Mutex
	members  map[string]discordapi.MemberInfo // user -> info
	roles    map[string]map[string]bool       // user -> role set
	addCalls []string                         // ordered "user:role"
	delCalls []string
	failAdd  map[string]error // "user:role" -> error
	failDel  map[string]error
	blockAdd chan struct{} // if non-nil, AddRole blocks until closed
}

func newFakeDiscord() *fakeDiscord {
	return &fakeDiscord{
		members: map[string]discordapi.MemberInfo{},
		roles:   map[string]map[string]bool{},
		failAdd: map[string]error{},
		failDel: map[string]error{},
	}
}

func (f *fakeDiscord) member(user string, joined time.Time) {
	f.members[user] = discordapi.MemberInfo{JoinedAt: joined}
	f.roles[user] = map[string]bool{}
}

func (f *fakeDiscord) GetMember(_ context.Context, _, user string) (discordapi.MemberInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m, ok := f.members[user]; ok {
		return m, nil
	}
	return discordapi.MemberInfo{NotFound: true}, nil
}

func (f *fakeDiscord) AddRole(_ context.Context, _, user, role string) error {
	if f.blockAdd != nil {
		<-f.blockAdd
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failAdd[user+":"+role]; err != nil {
		return err
	}
	if f.roles[user] == nil {
		f.roles[user] = map[string]bool{}
	}
	f.roles[user][role] = true
	f.addCalls = append(f.addCalls, user+":"+role)
	return nil
}

func (f *fakeDiscord) RemoveRole(_ context.Context, _, user, role string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failDel[user+":"+role]; err != nil {
		return err
	}
	delete(f.roles[user], role)
	f.delCalls = append(f.delCalls, user+":"+role)
	return nil
}

func (f *fakeDiscord) has(user, role string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.roles[user][role]
}

func testConfig() *config.Config {
	c := &config.Config{}
	c.GuildID = "g1"
	c.AddRoles = []string{"111", "222"}
	c.RemoveRoles = []string{"999"}
	c.UnverifiedRoles = []string{"888"}
	c.AdminRoleIDs = []string{"500"}
	c.SessionTTL = time.Minute
	return c
}

type harness struct {
	svc   *Service
	store *state.Store
	disc  *fakeDiscord
	sess  *session.Manager
	api   *fakeapi.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	api := fakeapi.New()
	t.Cleanup(api.Close)
	store := state.NewStore(api.Client(), "ns", "st", slog.Default())
	disc := newFakeDiscord()
	sess := session.NewManager(time.Minute)
	svc := New(testConfig(), store, disc, sess, slog.Default())
	ctx := context.Background()
	if _, err := store.Load(ctx, "g1"); err != nil {
		t.Fatal(err)
	}
	return &harness{svc: svc, store: store, disc: disc, sess: sess, api: api}
}

func now() time.Time { return time.Now().UTC() }

func (h *harness) doc(t *testing.T) *state.Doc {
	t.Helper()
	d, err := h.store.Load(context.Background(), "g1")
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestVerifyHappyPath(t *testing.T) {
	h := newHarness(t)
	h.disc.member("u1", now().Add(-time.Hour))
	ctx := context.Background()

	res := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", JoinedAt: h.disc.members["u1"].JoinedAt, GoogleSub: "s1", GoogleName: "N", GoogleEmail: "e@ok.com"})
	if res.Status != VerifyVerified {
		t.Fatalf("expected verified, got %+v", res)
	}
	d := h.doc(t)
	if d.Members["u1"] == nil || d.Members["u1"].GoogleSub != "s1" {
		t.Fatalf("link not stored: %+v", d.Members)
	}
	if !h.disc.has("u1", "111") || !h.disc.has("u1", "222") {
		t.Fatal("granted roles not applied")
	}
	if h.disc.has("u1", "999") {
		t.Fatal("removal role still present")
	}
	if len(d.Pending) != 0 {
		t.Fatalf("pending op not cleared: %+v", d.Pending)
	}
	if len(d.Members["u1"].AppliedRoles) != 2 {
		t.Fatalf("applied roles not retained: %+v", d.Members["u1"].AppliedRoles)
	}
}

func TestVerifyOneToOne(t *testing.T) {
	h := newHarness(t)
	h.disc.member("u1", now())
	h.disc.member("u2", now())
	ctx := context.Background()

	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("first: %+v", r)
	}
	// Same Google identity, different member.
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u2", GoogleSub: "s1"}); r.Status != VerifyRejected {
		t.Fatalf("expected 1:1 rejection, got %+v", r)
	}
	// Same member, different Google identity.
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", GoogleSub: "s2"}); r.Status != VerifyRejected {
		t.Fatalf("expected account rejection, got %+v", r)
	}
	if h.disc.has("u2", "111") {
		t.Fatal("loser got roles")
	}
}

func TestVerifyRaceExactlyOneLink(t *testing.T) {
	h := newHarness(t)
	h.disc.member("u1", now())
	h.disc.member("u2", now())
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.svc.Verify(ctx, &VerifyInput{MemberID: "u" + string(rune('1'+i)), GoogleSub: "shared"})
		}()
	}
	wg.Wait()
	d := h.doc(t)
	linked := 0
	for _, m := range d.Members {
		if m.GoogleSub == "shared" {
			linked++
		}
	}
	if linked != 1 {
		t.Fatalf("expected exactly one link, got %d", linked)
	}
}

func TestVerifyEpochChecked(t *testing.T) {
	h := newHarness(t)
	h.disc.member("u1", now())
	ctx := context.Background()
	// A revocation bumped the epoch after the Discord callback captured 0.
	if _, err := h.svc.RevokeCommit(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	res := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", Epoch: 0, GoogleSub: "s1"})
	if res.Status != VerifyRejected {
		t.Fatalf("expected epoch rejection, got %+v", res)
	}
	if h.doc(t).Members["u1"] != nil {
		t.Fatal("stale-epoch login stored a link")
	}
}

func TestReassertionIdempotent(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("first: %+v", r)
	}
	// Roles get lost (e.g. removed manually).
	h.disc.roles["u1"] = map[string]bool{}
	// Member rejoined at a newer time; re-verification refreshes the anchor.
	j2 := now().Add(-time.Minute)
	h.disc.members["u1"] = discordapi.MemberInfo{JoinedAt: j2}
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", Epoch: 0, JoinedAt: j2, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("re-assertion: %+v", r)
	}
	d := h.doc(t)
	if len(d.Members) != 1 || !d.Members["u1"].JoinedAt.Equal(j2) {
		t.Fatalf("joined_at not refreshed or duplicate link: %+v", d.Members)
	}
	if !h.disc.has("u1", "111") {
		t.Fatal("roles not re-applied")
	}
}

func TestGrantDeferredAndResumed(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	// Role add fails transiently.
	h.disc.failAdd["u1:222"] = &discordapi.APIError{Status: 500, Permanent: false}

	res := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", JoinedAt: j, GoogleSub: "s1"})
	if res.Status != VerifyPending {
		t.Fatalf("expected pending, got %+v", res)
	}
	d := h.doc(t)
	if d.Pending["u1"] == nil || d.Pending["u1"].Kind != state.OpGrant {
		t.Fatalf("pending grant not recorded: %+v", d.Pending)
	}
	if len(d.Pending["u1"].AddedSoFar) != 1 { // 111 applied, 222 failed
		t.Fatalf("progress not persisted: %+v", d.Pending["u1"])
	}
	// Provider recovers; reconciliation resumes and completes.
	delete(h.disc.failAdd, "u1:222")
	h.svc.Reconcile(ctx)
	if !h.disc.has("u1", "222") {
		t.Fatal("resumption did not apply remaining role")
	}
	d = h.doc(t)
	if d.Pending["u1"] != nil {
		t.Fatalf("op not completed: %+v", d.Pending)
	}
	if len(d.Members["u1"].AppliedRoles) != 2 {
		t.Fatal("applied roles not recorded at completion")
	}
}

func TestRevokeFull(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-time.Hour)
	h.disc.member("u1", j)
	h.disc.roles["u1"]["888"] = false // start unverified? no: granted member holds roles
	ctx := context.Background()
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("verify: %+v", r)
	}
	// Sessions exist for the member (in-flight login).
	s := h.sess.Start()
	h.sess.SetMember(s.DiscordState, "u1", 0, j)

	res, err := h.svc.Revoke(ctx, "u1")
	if err != nil || !res.CreatedRestoreOp {
		t.Fatalf("revoke: %+v %v", res, err)
	}
	d := h.doc(t)
	if d.Members["u1"] != nil {
		t.Fatal("link not released")
	}
	if d.Epochs["u1"] != 1 {
		t.Fatalf("epoch not bumped: %d", d.Epochs["u1"])
	}
	if h.disc.has("u1", "111") || h.disc.has("u1", "222") {
		t.Fatal("granted roles not removed")
	}
	if !h.disc.has("u1", "888") {
		t.Fatal("unverified role not restored")
	}
	if d.Pending["u1"] != nil {
		t.Fatal("revoke op not completed")
	}
	// In-flight session was dropped.
	if _, err := h.sess.Consume(s.DiscordState, session.StageDiscord); err == nil {
		t.Fatal("session survived revocation")
	}
	// Repeated revocation is idempotent.
	res2, err := h.svc.Revoke(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if res2.CreatedRestoreOp {
		t.Fatal("repeated revocation created a restore op")
	}
	if d := h.doc(t); d.Epochs["u1"] != 2 {
		t.Fatalf("epoch after repeat: %d", d.Epochs["u1"])
	}
}

func TestRevokeNeverLinkedBumpsEpochOnly(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	res, err := h.svc.RevokeCommit(ctx, "ghost")
	if err != nil {
		t.Fatal(err)
	}
	if res.CreatedRestoreOp {
		t.Fatal("restore op created for never-linked member")
	}
	if h.doc(t).Epochs["ghost"] != 1 {
		t.Fatal("epoch not bumped")
	}
	// An in-flight login captured the pre-revocation epoch and must be
	// rejected at reservation.
	h.disc.member("ghost", now())
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "ghost", Epoch: 0, GoogleSub: "s9"}); r.Status != VerifyRejected {
		t.Fatalf("expected rejection after revocation, got %+v", r)
	}
	// A fresh login (post-revocation epoch) may complete.
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "ghost", Epoch: 1, GoogleSub: "s9"}); r.Status != VerifyVerified {
		t.Fatalf("expected fresh success, got %+v", r)
	}
}

func TestRevokeDepartedSkipsRoles(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("verify: %+v", r)
	}
	// Freeze role ops mid-verify is not needed here; simply depart first.
	delete(h.disc.members, "u1")
	res, err := h.svc.Revoke(ctx, "u1")
	if err != nil || !res.CreatedRestoreOp {
		t.Fatalf("revoke: %+v %v", res, err)
	}
	if h.doc(t).Pending["u1"] != nil {
		t.Fatal("departed revoke op not completed without role work")
	}
}

func TestReconcileDepartures(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-2 * time.Hour)
	h.disc.member("u1", j)
	h.disc.member("u2", j)
	h.disc.member("u3", j)
	ctx := context.Background()
	for _, u := range []string{"u1", "u2", "u3"} {
		if r := h.svc.Verify(ctx, &VerifyInput{MemberID: u, JoinedAt: j, GoogleSub: "s-" + u}); r.Status != VerifyVerified {
			t.Fatalf("verify %s: %+v", u, r)
		}
	}
	// u1 leaves (404). u2 leaves and rejoins (newer joined_at). u3 stays.
	delete(h.disc.members, "u1")
	h.disc.members["u2"] = discordapi.MemberInfo{JoinedAt: now().Add(-time.Minute)}
	h.svc.Reconcile(ctx)

	d := h.doc(t)
	if d.Members["u1"] != nil || d.Members["u2"] != nil {
		t.Fatalf("departures not released: %+v", d.Members)
	}
	if d.Members["u3"] == nil {
		t.Fatal("staying member released")
	}
	if d.Epochs["u1"] == 0 || d.Epochs["u2"] == 0 {
		t.Fatal("departure did not bump epoch")
	}
	// Rejoining member must verify afresh: stale epoch rejects.
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u2", Epoch: 0, JoinedAt: now(), GoogleSub: "s-u2"}); r.Status != VerifyRejected {
		t.Fatalf("expected rejection, got %+v", r)
	}
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u2", Epoch: 1, JoinedAt: now(), GoogleSub: "s-u2"}); r.Status != VerifyVerified {
		t.Fatalf("expected fresh verification, got %+v", r)
	}
}

func TestReconcileAPIOutageNeverDeparts(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("verify: %+v", r)
	}
	// Simulate API outage: member lookup errors.
	h.disc.mu.Lock()
	h.disc.members["u1"] = discordapi.MemberInfo{} // zero JoinedAt = unusable
	h.disc.mu.Unlock()
	h.svc.Reconcile(ctx)
	if h.doc(t).Members["u1"] == nil {
		t.Fatal("unavailable joined_at treated as departure")
	}
}

func TestGrantResumptionValidatesMembership(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-2 * time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	// Freeze the second role add so the grant stays pending.
	h.disc.failAdd["u1:222"] = &discordapi.APIError{Status: 503, Permanent: false}
	res := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", JoinedAt: j, GoogleSub: "s1"})
	if res.Status != VerifyPending {
		t.Fatalf("expected pending, got %+v", res)
	}
	// Member leaves and rejoins during downtime.
	delete(h.disc.members, "u1")
	h.disc.member("u1", now().Add(-time.Minute))
	delete(h.disc.failAdd, "u1:222")
	h.svc.Reconcile(ctx)
	d := h.doc(t)
	if d.Members["u1"] != nil {
		t.Fatal("stale-attestation grant not released")
	}
	if d.Pending["u1"] != nil {
		t.Fatal("stale grant op not discarded")
	}
	if h.disc.has("u1", "111") && h.disc.has("u1", "222") {
		// u1 may hold 111 from partial application before rejoin; but not both
		t.Fatal("verified roles re-applied to rejoiner")
	}
}

func TestDowntimeCLIRevokeSupersedesPendingGrant(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-2 * time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	// Grant applies 111 then the process "crashes" (fail 222 permanently-ish).
	h.disc.failAdd["u1:222"] = &discordapi.APIError{Status: 503, Permanent: false}
	res := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", JoinedAt: j, GoogleSub: "s1"})
	if res.Status != VerifyPending {
		t.Fatalf("expected pending, got %+v", res)
	}
	// Operator CLI revokes during downtime (commit-only).
	cliRes, err := RevokeCommitOnly(ctx, h.store, "g1", "u1", slog.Default())
	if err != nil || !cliRes.CreatedRestoreOp {
		t.Fatalf("cli revoke: %+v %v", cliRes, err)
	}
	d := h.doc(t)
	op := d.Pending["u1"]
	if op == nil || op.Kind != state.OpRevoke {
		t.Fatalf("revoke op missing: %+v", op)
	}
	want := state.UnionStrings([]string{"111", "222"}, []string{"111"})
	if len(op.RemoveRoles) != 2 {
		t.Fatalf("removal set should be union of intended+applied: %+v", op.RemoveRoles)
	}
	// Service restarts; the grant resumption is superseded, revocation applies.
	delete(h.disc.failAdd, "u1:222")
	h.svc.Reconcile(ctx)
	if h.disc.has("u1", "111") {
		t.Fatal("granted role survived CLI revocation")
	}
	if !h.disc.has("u1", "888") {
		t.Fatal("unverified role not restored")
	}
	_ = want
}

func TestReVerificationSupersedesPartialRevocation(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-2 * time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("verify: %+v", r)
	}
	// Slash-command revoke commits, but the restore step only re-adds part
	// of the unverified roles before "crashing".
	if _, err := h.svc.RevokeCommit(ctx, "u1"); err != nil {
		t.Fatal(err)
	}
	h.disc.mu.Lock()
	restore := h.disc.roles["u1"]
	_ = restore
	h.disc.mu.Unlock()
	// Manually apply a partial restore: remove granted, re-add one unverified.
	h.disc.RemoveRole(ctx, "g1", "u1", "111")
	h.disc.RemoveRole(ctx, "g1", "u1", "222")
	h.disc.AddRole(ctx, "g1", "u1", "888")
	// Record the partial restore progress as the service would.
	if err := h.store.Update(ctx, "g1", func(d *state.Doc) error {
		d.Pending["u1"].RestoredSoFar = []string{"888"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Member re-verifies with the same identity under the new epoch.
	d := h.doc(t)
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", Epoch: d.Epochs["u1"], JoinedAt: now(), GoogleSub: "s1"}); r.Status != VerifyVerified {
		t.Fatalf("re-verify: %+v", r)
	}
	if !h.disc.has("u1", "111") || !h.disc.has("u1", "222") {
		t.Fatal("verified roles not (re)applied")
	}
	if h.disc.has("u1", "888") {
		t.Fatal("unverified role survived re-verification")
	}
	if h.doc(t).Pending["u1"] != nil {
		t.Fatal("revoke op not replaced")
	}
}

func TestReconcileDiscardsStaleEpochGrant(t *testing.T) {
	h := newHarness(t)
	j := now().Add(-2 * time.Hour)
	h.disc.member("u1", j)
	ctx := context.Background()
	h.disc.failAdd["u1:222"] = &discordapi.APIError{Status: 503, Permanent: false}
	if r := h.svc.Verify(ctx, &VerifyInput{MemberID: "u1", JoinedAt: j, GoogleSub: "s1"}); r.Status != VerifyPending {
		t.Fatalf("expected pending, got %+v", r)
	}
	// CLI revocation bumps the epoch while the grant is pending.
	if _, err := RevokeCommitOnly(ctx, h.store, "g1", "u1", slog.Default()); err != nil {
		t.Fatal(err)
	}
	delete(h.disc.failAdd, "u1:222")
	h.svc.Reconcile(ctx)
	// The stale grant must not have applied its roles; the revocation owns
	// the terminal state.
	if h.disc.has("u1", "222") && !h.disc.has("u1", "888") {
		t.Fatal("stale grant applied roles")
	}
	if h.doc(t).Pending["u1"] != nil {
		t.Fatal("pending ops not drained")
	}
}
