package daemon

import (
	"context"
	"fmt"

	"corpvpn/internal/verbs"
)

// WedgeWatcher owns the wedge state machine across cycles.
type WedgeWatcher struct {
	TestHost      string // probed through the scoped path and the forwarder
	ForwarderAddr string // "127.0.0.1"
	// ScopedLookup answers whether the system resolver path resolves
	// TestHost (dscacheutil-backed; wired to verbs.ScopedLookupWorks).
	ScopedLookup func(ctx context.Context, host string) bool
	// ForwarderAnswers answers whether the forwarder resolves TestHost
	// (pure Go resolver to ForwarderAddr).
	ForwarderAnswers func(ctx context.Context, host string) bool
	// Kick runs verbs.ResolverKick. HostsUp runs verbs.HostsUp.
	Kick    func() error
	HostsUp func(entries []verbs.HostsEntry) error
	Notify  func(msg string)

	LastErr error // last recorded repair error, cleared when healthy again

	kickedCycle    int  // cycle index of the last kick; 0 = no active episode
	hostsInstalled bool // hosts fallback already installed this episode
	notified       bool // user already notified this episode
}

// Cycle runs one detection round. Cycle numbering starts at 1 and must
// increase across calls. State machine: healthy -> (scoped fails &&
// forwarder ok) -> kick, remember cycle. Next cycle still wedged ->
// hosts fallback from cache, notify once. Scoped healthy again ->
// state resets; hosts block stays until root-hosts-down (down path).
func (w *WedgeWatcher) Cycle(ctx context.Context, n int, cache []verbs.HostsEntry) {
	if w.ScopedLookup(ctx, w.TestHost) {
		// Healthy: reset the episode. A previously installed hosts
		// block stays until root-hosts-down (the down path).
		w.kickedCycle = 0
		w.hostsInstalled = false
		w.notified = false
		w.LastErr = nil
		return
	}
	if !w.ForwarderAnswers(ctx, w.TestHost) {
		// Scoped fails but the forwarder does not answer either:
		// not a resolver wedge (failure classification owns that).
		return
	}
	if w.kickedCycle == 0 {
		if err := w.Kick(); err != nil {
			w.LastErr = err
		}
		w.kickedCycle = n
		return
	}
	// Wedge survived the kick for one probe interval.
	if w.hostsInstalled {
		return
	}
	if err := w.HostsUp(cache); err != nil {
		// Recorded, not fatal: the next cycle retries the install.
		w.LastErr = err
		return
	}
	w.hostsInstalled = true
	if !w.notified {
		w.notified = true
		w.Notify(fmt.Sprintf("corpvpn: system resolver wedged; bank names pinned to /etc/hosts from forwarder cache (test host %s)", w.TestHost))
	}
}
