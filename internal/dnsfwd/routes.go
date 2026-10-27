package dnsfwd

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
)

// RouteInstaller mutates and inspects the Mac route table. Production
// impl shells out to /sbin/route; tests inject fakes.
type RouteInstaller interface {
	// Add installs a /32 for addr via gw. Returns (added, error).
	Add(addr [4]byte, gw [4]byte) (bool, error)
	// RouteOf returns the gateway and matched destination the system
	// currently uses for addr, as `route -n get` reports them: dest is
	// the matched "destination:" line, "default" when the answer fell
	// back to the default route (nothing owns addr specifically).
	RouteOf(addr [4]byte) (gw string, dest string, err error)
	// Remove deletes the /32 for addr.
	Remove(addr [4]byte) error
}

// RouteState persists dynamic /32s so down removes exactly what was
// added. Lines are "<ip>/32", the same file and format the S5
// recorded-routes state uses (hostops), so root-net-down's RemoveNet
// removes the forwarder's routes too. Appended, deduplicated.
type RouteState struct {
	Path string

	// EnsureRoute is invoked from per-packet Forwarder goroutines.
	mu        sync.Mutex
	contested map[[4]byte]bool // already notified this episode
}

// ipString renders a dotted-quad, the format used both on the wire to
// notify and in the state file.
func ipString(a [4]byte) string {
	return netip.AddrFrom4(a).String()
}

// EnsureRoute is the OnAnswer sink for the Forwarder. Owns the
// once-per-episode contested notification dedup. An episode for addr
// lasts until RemoveAll or until addr is actually installed.
//
// Reclaim semantics (user-approved 2026-10-27): a bank-derived address
// already routed via the VM gateway is steady state; route-get failure
// and the "destination: default" fallback mean nothing owns the address,
// so ours is added directly; a specific foreign-held route (equal or
// covering) is fought -- the foreign path is the broken one -- with the
// address notified once per episode for visibility. Only actually
// installed addresses are recorded.
func (r *RouteState) EnsureRoute(addr [4]byte, gw [4]byte, ri RouteInstaller, notify func(string)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cur, dest, err := ri.RouteOf(addr)
	switch {
	case err == nil && cur == ipString(gw):
		// Steady state. S5's ApplyNetReport may have rewritten the
		// shared file in between, dropping our line; appendLocked
		// re-records the address (idempotent, scans the file first)
		// so down's RemoveNet does not leak the /32.
		_ = r.appendLocked(addr)
		return
	case err != nil, dest == "default":
		// Route unknown, or macOS answered with the default-route entry:
		// nothing conflicts, install ours directly.
		r.addLocked(addr, gw, ri)
	default:
		// A specific route (equal or covering) via another gateway:
		// reclaim it. The remove may answer "not in table" when only a
		// covering prefix exists -- an exact /32 delete never matches
		// those -- and our /32 still wins by longest-prefix match.
		r.notifyContestedLocked(addr, notify)
		if rerr := ri.Remove(addr); rerr != nil && !routeNoMatch(rerr) {
			return
		}
		r.addLocked(addr, gw, ri)
	}
}

// addLocked installs the /32 and records it only when actually added; a
// successful install starts a fresh contested episode.
func (r *RouteState) addLocked(addr, gw [4]byte, ri RouteInstaller) {
	added, err := ri.Add(addr, gw)
	if err != nil || !added {
		return
	}
	// If recording fails the route stays installed but untracked; down
	// will not remove it, which is safer than skipping the install.
	if err := r.appendLocked(addr); err != nil {
		return
	}
	delete(r.contested, addr)
}

// routeNoMatch reports route(8)'s "not in table" reply: the delete found
// nothing exact to remove.
func routeNoMatch(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "not in table")
}

func (r *RouteState) notifyContestedLocked(addr [4]byte, notify func(string)) {
	if r.contested[addr] {
		return
	}
	if r.contested == nil {
		r.contested = make(map[[4]byte]bool)
	}
	r.contested[addr] = true
	if notify != nil {
		notify(ipString(addr))
	}
}

// List returns the recorded addresses in file order.
func (r *RouteState) List() [][4]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listLocked()
}

// listLocked parses the state file; a missing or unreadable file simply
// means nothing is recorded. Both this package's "<ip>/32" lines and
// legacy plain-IP lines parse; anything else is skipped.
func (r *RouteState) listLocked() [][4]byte {
	data, err := os.ReadFile(r.Path)
	if err != nil {
		return nil
	}
	var out [][4]byte
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if p, perr := netip.ParsePrefix(line); perr == nil {
			if !p.Addr().Is4() || !p.IsSingleIP() {
				continue
			}
			out = append(out, p.Addr().As4())
			continue
		}
		ip, err := netip.ParseAddr(line)
		if err != nil || !ip.Is4() {
			continue
		}
		out = append(out, ip.As4())
	}
	return out
}

// appendLocked appends addr to the state file unless already recorded,
// as "<ip>/32" so hostops RemoveNet (strict prefix parsing) removes it.
func (r *RouteState) appendLocked(addr [4]byte) error {
	for _, a := range r.listLocked() {
		if a == addr {
			return nil
		}
	}
	f, err := os.OpenFile(r.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, netip.PrefixFrom(netip.AddrFrom4(addr), 32))
	return err
}

// RemoveAll deletes every recorded route and truncates the state file.
// A route that fails to delete does not block the rest; the file is
// reset either way so down stays idempotent.
func (r *RouteState) RemoveAll(ri RouteInstaller) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var errs []error
	for _, a := range r.listLocked() {
		if err := ri.Remove(a); err != nil {
			errs = append(errs, fmt.Errorf("remove route %s: %w", ipString(a), err))
		}
	}
	if err := os.WriteFile(r.Path, nil, 0o644); err != nil {
		errs = append(errs, fmt.Errorf("truncate route state %s: %w", r.Path, err))
	}
	r.contested = nil // RemoveAll ends every episode
	return errors.Join(errs...)
}
