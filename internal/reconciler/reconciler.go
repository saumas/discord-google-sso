// Package reconciler drives the membership sweep: a startup pass plus a
// five-minute ticker (the interval is a scheduling target and configurable;
// the ticker is injectable/advanceable in tests).
package reconciler

import (
	"context"
	"log/slog"
	"time"

	"github.com/saumas/discord-google-sso/internal/core"
)

// Reconciler runs core.Service.Reconcile on a ticker.
type Reconciler struct {
	svc      *core.Service
	interval time.Duration
	log      *slog.Logger
}

// New returns a Reconciler.
func New(svc *core.Service, interval time.Duration, log *slog.Logger) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	return &Reconciler{svc: svc, interval: interval, log: log}
}

// Run performs the startup pass, then ticks until the context is canceled.
func (r *Reconciler) Run(ctx context.Context) {
	r.svc.Reconcile(ctx)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.svc.Reconcile(ctx)
		}
	}
}
