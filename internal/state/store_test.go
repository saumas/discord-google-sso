package state

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/saumas/discord-google-sso/internal/fakeapi"
)

func newTestStore(t *testing.T) (*Store, *fakeapi.Server) {
	t.Helper()
	srv := fakeapi.New()
	t.Cleanup(srv.Close)
	return NewStore(srv.Client(), "test-ns", "state-secret", nil), srv
}

func TestLoadCreatesMissing(t *testing.T) {
	store, _ := newTestStore(t)
	doc, err := store.Load(context.Background(), "guild-1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if doc.GuildID != "guild-1" || doc.SchemaVersion != SchemaVersion {
		t.Fatalf("unexpected doc: %+v", doc)
	}
}

func TestLoadRejectsForeignGuild(t *testing.T) {
	store, _ := newTestStore(t)
	if _, err := store.Load(context.Background(), "guild-1"); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := store.Load(context.Background(), "guild-2"); err == nil {
		t.Fatal("expected foreign-guild refusal")
	}
}

// TestLoadRejectsBadState covers the corrupt/foreign state refusals that
// share the same shape: install a bad payload, expect a clear Load error
// rather than a reset.
func TestLoadRejectsBadState(t *testing.T) {
	cases := []struct {
		name    string
		install func(t *testing.T, sec *corev1.Secret)
	}{
		{
			name: "corrupt payload",
			install: func(_ *testing.T, sec *corev1.Secret) {
				sec.Data[DataKey] = []byte("not gzip at all")
			},
		},
		{
			name: "unknown schema version",
			install: func(t *testing.T, sec *corev1.Secret) {
				var doc Doc
				doc.SchemaVersion = 99
				doc.GuildID = "g"
				doc.Members = map[string]*Member{}
				sec.Data[DataKey] = mustGzip(t, &doc)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, srv := newTestStore(t)
			ctx := context.Background()
			if _, err := store.Load(ctx, "g"); err != nil {
				t.Fatalf("load: %v", err)
			}
			sec, err := srv.Client().CoreV1().Secrets("test-ns").Get(ctx, "state-secret", metav1.GetOptions{})
			if err != nil {
				t.Fatal(err)
			}
			tc.install(t, sec)
			if _, err := srv.Client().CoreV1().Secrets("test-ns").Update(ctx, sec, metav1.UpdateOptions{}); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(ctx, "g"); err == nil {
				t.Fatalf("%s accepted", tc.name)
			}
		})
	}
}

func mustGzip(t *testing.T, doc *Doc) []byte {
	t.Helper()
	sec, err := secretForDoc(doc)
	if err != nil {
		t.Fatal(err)
	}
	return sec.Data[DataKey]
}

// secretForDoc mirrors the store's serialization for test setup.
func secretForDoc(doc *Doc) (*corev1.Secret, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(raw); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return &corev1.Secret{Data: map[string][]byte{DataKey: buf.Bytes()}}, nil
}

func TestUpdateConcurrentPreservesBoth(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := store.Load(ctx, "g"); err != nil {
		t.Fatal(err)
	}
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := store.Update(ctx, "g", func(d *Doc) error {
				d.Members[fmt.Sprintf("user-%d", i)] = &Member{GoogleSub: fmt.Sprintf("sub-%d", i)}
				return nil
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent update: %v", err)
	}
	doc, err := store.Load(ctx, "g")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Members) != n {
		t.Fatalf("expected %d members, got %d", n, len(doc.Members))
	}
}

func TestUpdateEnforcesUniquenessAtomically(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := store.Load(ctx, "g"); err != nil {
		t.Fatal(err)
	}
	// Two racing writers link the same Google sub to two Discord users.
	var wg sync.WaitGroup
	results := make([]bool, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := store.Update(ctx, "g", func(d *Doc) error {
				d.Members[fmt.Sprintf("user-%d", i)] = &Member{GoogleSub: "shared-sub"}
				return d.Validate("g")
			})
			results[i] = err == nil
		}()
	}
	wg.Wait()
	won := 0
	for _, ok := range results {
		if ok {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("expected exactly one winner, got %d", won)
	}
}

func TestUpdateRejectsTooLarge(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := store.Load(ctx, "g"); err != nil {
		t.Fatal(err)
	}
	// Incompressible member data large enough to exceed the budget.
	huge := make([]byte, MaxSecretBytes)
	if _, err := rand.Read(huge); err != nil {
		t.Fatal(err)
	}
	name := hex.EncodeToString(huge)
	err := store.Update(ctx, "g", func(d *Doc) error {
		d.Members["u"] = &Member{GoogleSub: "s", GoogleName: name}
		return nil
	})
	if err == nil {
		t.Fatal("expected size rejection")
	}
	// Existing state preserved.
	doc, err := store.Load(ctx, "g")
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Members) != 0 {
		t.Fatalf("expected no members, got %d", len(doc.Members))
	}
}

func TestRestartPreservesState(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := store.Load(ctx, "g"); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(ctx, "g", func(d *Doc) error {
		d.Members["u1"] = &Member{GoogleSub: "s1", JoinedAt: time.Now().UTC()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A "restart": a new Store instance against the same API server.
	store2 := NewStore(store.client, "test-ns", "state-secret", nil)
	doc, err := store2.Load(ctx, "g")
	if err != nil {
		t.Fatal(err)
	}
	if doc.Members["u1"] == nil || doc.Members["u1"].GoogleSub != "s1" {
		t.Fatalf("state lost across restart: %+v", doc)
	}
}
