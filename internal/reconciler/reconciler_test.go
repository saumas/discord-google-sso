package reconciler

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saumas/discord-google-sso/internal/core"
)

type countingSvc struct{ calls atomic.Int64 }

func (c *countingSvc) Reconcile(context.Context) { c.calls.Add(1) }

// newTestReconciler avoids constructing a full core.Service just to drive the
// loop; the seam takes the interface, but New expects *core.Service for
// production wiring, so tests build the struct directly.
func newTestReconciler(svc reconcileAPI, interval time.Duration) *Reconciler {
	return &Reconciler{svc: svc, interval: interval}
}

func TestLoopRunsStartupPassThenOneDispatchPerTick(t *testing.T) {
	svc := &countingSvc{}
	r := newTestReconciler(svc, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() { r.loop(ctx, ticks); close(done) }()

	// No tick yet: no dispatch beyond the caller-controlled startup pass
	// (Run's startup call is not part of loop; loop only reacts to ticks).
	if got := svc.calls.Load(); got != 0 {
		t.Fatalf("dispatched before any tick: %d", got)
	}
	for range 3 {
		ticks <- time.Time{}
	}
	deadline := time.Now().Add(time.Second)
	for svc.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := svc.calls.Load(); got != 3 {
		t.Fatalf("want 3 dispatches after 3 ticks, got %d", got)
	}
	cancel()
	<-done
}

func TestLoopStopsOnContextCancel(t *testing.T) {
	svc := &countingSvc{}
	r := newTestReconciler(svc, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time, 1) // buffered: the late send must not block
	done := make(chan struct{})
	go func() { r.loop(ctx, ticks); close(done) }()

	cancel()
	select {
	case <-done:
		// Loop exited without consuming a tick.
	case <-time.After(time.Second):
		t.Fatal("loop did not stop on cancel")
	}
	// A late tick must not dispatch after cancellation.
	ticks <- time.Time{}
	// Give any (incorrect) dispatch a moment to land, then assert none did.
	time.Sleep(50 * time.Millisecond)
	if got := svc.calls.Load(); got != 0 {
		t.Fatalf("dispatched after cancel: %d", got)
	}
}

// The production constructor wiring is exercised separately; this
// assertion keeps the core import honest about the loop's seam.
var _ reconcileAPI = (*core.Service)(nil)
