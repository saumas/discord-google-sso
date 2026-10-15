// Package reconciler drives the membership sweep: a startup pass plus a
// five-minute ticker (the interval is a scheduling target and configurable).
// The tick loop is split from the ticker construction so tests can drive it
// with a controlled channel instead of real sleeps.
package reconciler

import (
	"context"
	"time"

	"github.com/saumas/discord-google-sso/internal/core"
)

// reconcileAPI is the surface the reconciler drives (satisfied by
// *core.Service; an interface keeps the loop testable).
type reconcileAPI interface {
	Reconcile(context.Context)
}

// Reconciler runs core.Service.Reconcile on a ticker.
type Reconciler struct {
	svc      reconcileAPI
	interval time.Duration
}

// New returns a Reconciler.
func New(svc *core.Service, interval time.Duration) *Reconciler {
	return &Reconciler{svc: svc, interval: interval}
}

// Run performs the startup pass, then ticks until the context is canceled.
func (r *Reconciler) Run(ctx context.Context) {
	r.svc.Reconcile(ctx)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	r.loop(ctx, t.C)
}

// loop is the testable core: one Reconcile dispatch per received tick.
func (r *Reconciler) loop(ctx context.Context, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			r.svc.Reconcile(ctx)
		}
	}
}
