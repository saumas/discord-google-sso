package state

import (
	"bytes"
	"compress/gzip"
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/saumas/discord-google-sso/internal/fakeapi"
)

func mustGzipRaw(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestLoadRejectsMissingMaps feeds a schema-valid document whose Epochs and
// Pending maps are absent (as a hand-restored or externally edited Secret
// could produce) and asserts a clear refusal rather than a later panic on
// the first write to a nil map.
func TestLoadRejectsMissingMaps(t *testing.T) {
	store, srv := newTestStore(t)
	ctx := context.Background()
	if _, err := store.Load(ctx, "g"); err != nil {
		t.Fatalf("load: %v", err)
	}
	// Overwrite with a document missing the epochs/pending keys.
	partial := `{"schemaVersion":1,"guildID":"g","members":{}}`
	sec, err := srv.Client().CoreV1().Secrets("test-ns").Get(ctx, "state-secret", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	sec.Data[DataKey] = mustGzipRaw(t, []byte(partial))
	if _, err := srv.Client().CoreV1().Secrets("test-ns").Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ctx, "g"); err == nil {
		t.Fatal("expected refusal for document missing epochs/pending maps")
	}
	// The same refusal applies on the update path (mutate must never run
	// against a nil map).
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_ = store.Update(ctx, "g", func(d *Doc) error {
			d.Epochs["u"] = 1 // would panic on a nil map
			return nil
		})
	}()
	if panicked {
		t.Fatal("update panicked on nil map instead of refusing cleanly")
	}
}

func TestApplyDepartureReleaseGuardsAttestation(t *testing.T) {
	j1 := time.Now().UTC().Add(-time.Hour)
	j2 := time.Now().UTC()

	// A release decided from the current attestation fires.
	doc := NewDoc("g")
	doc.Members["u1"] = &Member{GoogleSub: "s1", JoinedAt: j1}
	doc.Epochs["u1"] = 3
	if !doc.ApplyDepartureRelease("u1", j1) {
		t.Fatal("expected release with the current attestation")
	}
	if doc.Members["u1"] != nil || doc.Epochs["u1"] != 4 {
		t.Fatalf("release did not apply: %+v", doc)
	}

	// A release decided from a stale attestation must not fire after the
	// link was refreshed by a re-verification (newer joined_at).
	doc2 := NewDoc("g")
	doc2.Members["u1"] = &Member{GoogleSub: "s1", JoinedAt: j2}
	doc2.Epochs["u1"] = 3
	if doc2.ApplyDepartureRelease("u1", j1) {
		t.Fatal("stale attestation released a refreshed link")
	}
	if doc2.Members["u1"] == nil || doc2.Epochs["u1"] != 3 {
		t.Fatalf("stale release mutated state: %+v", doc2)
	}
	if doc2.ApplyDepartureRelease("ghost", j2) {
		t.Fatal("released an unknown member")
	}
}

// TestLoadCreateRaceReturnsPersistedDoc covers the create race: the first
// GET misses, the Create loses to another writer, and Load must return the
// persisted document rather than a locally built empty one.
func TestLoadCreateRaceReturnsPersistedDoc(t *testing.T) {
	srv := fakeapi.New()
	t.Cleanup(srv.Close)
	winner := NewStore(srv.Client(), "test-ns", "state-secret", nil)
	loser := NewStore(srv.Client(), "test-ns", "state-secret", nil)
	ctx := context.Background()

	// The winner creates the Secret with data first.
	if err := winner.Update(ctx, "g", func(d *Doc) error {
		d.Members["u1"] = &Member{GoogleSub: "s1", JoinedAt: time.Now().UTC()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The loser's first GET misses (simulated), so it goes down the create
	// path and hits AlreadyExists — it must re-read and see the winner's
	// document.
	srv.HideNextGet.Store(true)
	doc, err := loser.Load(ctx, "g")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if doc.Members["u1"] == nil || doc.Members["u1"].GoogleSub != "s1" {
		t.Fatalf("load returned stale document after create race: %+v", doc.Members)
	}
}
