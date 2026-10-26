package daemon

import (
	"context"
	"errors"
	"time"
)

// Runner is the injected reconcile: runs S1-S6, returns per-step
// results. Production wires the existing steps; tests inject fakes.
type Runner func(ctx context.Context, report func(step string, err error)) error

// Daemon is the desired-state converge loop.
type Daemon struct {
	DesiredPath, StatusPath string
	Probe                   func(ctx context.Context) error
	Reconcile               Runner
	Interval                time.Duration // default 10s
	Backoff                 time.Duration // after a failed reconcile, default 30s
	// Sleep is the pause between loops, injectable as a fake clock in
	// tests; defaults to an interruptible sleep.
	Sleep func(ctx context.Context, d time.Duration)
	// EachTick, when set, runs once per iteration after the probe while
	// desired=up. Nil-safe optional accessory: design.md drives the wedge
	// watcher this way, one cycle per probe interval.
	EachTick func(ctx context.Context)
}

// Run blocks until ctx is cancelled: each loop reads the desired state,
// while up probes and converges, while down only records status. The
// probe timeout is d.Probe's own.
func (d *Daemon) Run(ctx context.Context) error {
	interval := d.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	backoff := d.Backoff
	if backoff <= 0 {
		backoff = 30 * time.Second
	}
	sleep := d.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, dur time.Duration) {
			timer := time.NewTimer(dur)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		desired, err := ReadDesired(d.DesiredPath)
		if err != nil {
			// Fail-safe: an unreadable desired file must never trigger repairs.
			desired = Down
		}
		st := Status{Desired: desired, UpdatedAt: time.Now()}
		if desired != Up {
			// desired=down: record status only, touch nothing else.
			_ = WriteStatus(d.StatusPath, st)
			sleep(ctx, interval)
			continue
		}
		probeErr := d.probe(ctx)
		var steps map[string]string
		pause := interval
		if probeErr != nil {
			steps = d.reconcile(ctx)
			probeErr = d.probe(ctx) // re-probe once after the reconcile pass
			if probeErr != nil {
				st.Probe = probeErr.Error()
				pause = backoff
			}
		}
		if probeErr == nil {
			st.Probe = "ok"
		}
		st.Steps = steps
		// A failed status write is not fatal: the next loop rewrites it.
		_ = WriteStatus(d.StatusPath, st)
		if d.EachTick != nil {
			d.EachTick(ctx)
		}
		sleep(ctx, pause)
	}
}

func (d *Daemon) probe(ctx context.Context) error {
	if d.Probe == nil {
		return errors.New("daemon: probe not wired")
	}
	return d.Probe(ctx)
}

// reconcile runs the injected Runner and collects per-step results;
// an unexported nil-Reconcile guard keeps a miswired daemon from
// panicking into a launchd restart loop.
func (d *Daemon) reconcile(ctx context.Context) map[string]string {
	steps := map[string]string{}
	if d.Reconcile == nil {
		return steps
	}
	d.Reconcile(ctx, func(step string, err error) {
		if err != nil {
			steps[step] = err.Error()
			return
		}
		steps[step] = "ok"
	})
	return steps
}
