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
	// GatewayOf returns the gateway the system currently uses for addr;
	// empty when the route is a cloned interface route.
	GatewayOf(addr [4]byte) (string, error)
	// Remove deletes the /32 for addr.
	Remove(addr [4]byte) error
}

// RouteState persists dynamic /32s so down removes exactly what was
// added. One address per line, appended, deduplicated.
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
// lasts until RemoveAll or until addr is actually installed: a
// foreign-owned or interface-cloned address is reported via notify once
// per episode and never shadowed with a corpvpn route.
func (r *RouteState) EnsureRoute(addr [4]byte, gw [4]byte, ri RouteInstaller, notify func(string)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cur, err := ri.GatewayOf(addr)
	if err == nil {
		if cur == ipString(gw) {
			return // already routed via the VM gateway
		}
		r.notifyContestedLocked(addr, notify)
		return
	}

	// Route unknown: install it, and record only what we actually added.
	added, err := ri.Add(addr, gw)
	if err != nil || !added {
		return
	}
	// If recording fails the route stays installed but untracked; down
	// will not remove it, which is safer than skipping the install.
	if err := r.appendLocked(addr); err != nil {
		return
	}
	delete(r.contested, addr) // a successful install starts a fresh episode
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
// means nothing is recorded.
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
		ip, err := netip.ParseAddr(line)
		if err != nil || !ip.Is4() {
			continue
		}
		out = append(out, ip.As4())
	}
	return out
}

// appendLocked appends addr to the state file unless already recorded.
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
	_, err = fmt.Fprintln(f, ipString(addr))
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
