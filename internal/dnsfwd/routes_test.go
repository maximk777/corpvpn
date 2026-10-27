package dnsfwd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// fakeInstaller is an in-memory RouteInstaller. routes maps an address to
// the gateway its /32 points at; an absent address means "no specific
// route". defaultGW non-empty emulates the macOS `route -n get` fallback:
// the answer is the DEFAULT route entry (dest "default") with the LAN
// router as gateway.
type fakeInstaller struct {
	routes    map[[4]byte][4]byte
	defaultGW string
	addErr    error
	adds      int
	removed   [][4]byte
}

func newFakeInstaller() *fakeInstaller {
	return &fakeInstaller{routes: make(map[[4]byte][4]byte)}
}

func (f *fakeInstaller) Add(addr, gw [4]byte) (bool, error) {
	f.adds++
	if f.addErr != nil {
		return false, f.addErr
	}
	f.routes[addr] = gw
	return true, nil
}

func (f *fakeInstaller) RouteOf(addr [4]byte) (string, string, error) {
	if f.defaultGW != "" {
		return f.defaultGW, "default", nil
	}
	if gw, ok := f.routes[addr]; ok {
		return ipString(gw), ipString(addr) + "/32", nil
	}
	return "", "", fmt.Errorf("no route to %s", ipString(addr))
}

func (f *fakeInstaller) Remove(addr [4]byte) error {
	delete(f.routes, addr)
	f.removed = append(f.removed, addr)
	return nil
}

func (f *fakeInstaller) has(addr [4]byte) bool {
	_, ok := f.routes[addr]
	return ok
}

var (
	addrA = [4]byte{10, 15, 0, 64}
	addrB = [4]byte{10, 15, 0, 65}
	vmGW  = [4]byte{192, 168, 64, 1}
)

func TestEnsureRouteAddsAndRecords(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	ri := newFakeInstaller()

	rs.EnsureRoute(addrA, vmGW, ri, nil)

	if !ri.has(addrA) {
		t.Fatal("route for 10.15.0.64 was not installed")
	}
	data, err := os.ReadFile(rs.Path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	// CIDR lines: the state file is shared with the S5 recorded-routes
	// file, and hostops RemoveNet strict-parses prefixes.
	if got, want := string(data), "10.15.0.64/32\n"; got != want {
		t.Errorf("state file = %q, want %q", got, want)
	}
	if got := rs.List(); len(got) != 1 || got[0] != addrA {
		t.Errorf("List() = %v, want [10.15.0.64]", got)
	}
}

func TestEnsureRouteRepeatedAnswerIsNoOp(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	ri := newFakeInstaller()

	rs.EnsureRoute(addrA, vmGW, ri, nil)
	rs.EnsureRoute(addrA, vmGW, ri, nil)

	if ri.adds != 1 {
		t.Errorf("Add calls = %d, want 1", ri.adds)
	}
	data, _ := os.ReadFile(rs.Path)
	if got, want := string(data), "10.15.0.64/32\n"; got != want {
		t.Errorf("state file = %q, want %q (repeated answer must not duplicate)", got, want)
	}
}

// S5's ApplyNetReport rewrites the shared state file between forwarder
// passes, dropping the forwarder's own /32 line. The steady-state answer
// (route already ours) must re-append the address, or down's RemoveNet
// parsing that file leaks the /32.
func TestEnsureRouteSteadyStateReAppendsAfterTruncation(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	ri := newFakeInstaller()

	rs.EnsureRoute(addrA, vmGW, ri, nil) // installed and recorded

	// S5 truncation: the shared file is rewritten with only hostops
	// entries; our /32 line is gone while the route itself still lives.
	if err := os.WriteFile(rs.Path, []byte("10.52.0.0/24\n"), 0o644); err != nil {
		t.Fatalf("simulate S5 truncation: %v", err)
	}

	rs.EnsureRoute(addrA, vmGW, ri, nil) // steady state: gw ours

	if ri.adds != 1 {
		t.Errorf("Add calls = %d, want 1 (steady state must not reinstall)", ri.adds)
	}
	data, _ := os.ReadFile(rs.Path)
	if got, want := string(data), "10.52.0.0/24\n10.15.0.64/32\n"; got != want {
		t.Errorf("state file = %q, want %q (steady state must re-append the /32 and keep the hostops entry)", got, want)
	}
}

// A foreign specific route for a bank address is reclaimed (user-approved
// 2026-10-27): Remove + Add, notified once, and the /32 recorded so down
// removes it.
func TestEnsureRouteForeignRouteIsReclaimed(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	foreignGW := [4]byte{192, 168, 176, 1}
	ri := newFakeInstaller()
	ri.routes[addrA] = foreignGW

	var notified []string
	notify := func(addr string) { notified = append(notified, addr) }

	rs.EnsureRoute(addrA, vmGW, ri, notify)

	if ri.adds != 1 {
		t.Errorf("Add calls = %d, want 1 (foreign-held route must be reclaimed)", ri.adds)
	}
	if len(ri.removed) != 1 || ri.removed[0] != addrA {
		t.Errorf("Remove calls = %v, want exactly [10.15.0.64]", ri.removed)
	}
	if len(notified) != 1 || notified[0] != "10.15.0.64" {
		t.Errorf("notify calls = %v, want exactly once with 10.15.0.64", notified)
	}
	if !ri.has(addrA) {
		t.Error("route not re-added after reclaim")
	}
	data, _ := os.ReadFile(rs.Path)
	if got, want := string(data), "10.15.0.64/32\n"; got != want {
		t.Errorf("state file = %q, want %q (reclaimed route must be recorded)", got, want)
	}

	// Next answer: the route is ours now -- steady state, nothing moves.
	rs.EnsureRoute(addrA, vmGW, ri, notify)
	if ri.adds != 1 || len(ri.removed) != 1 || len(notified) != 1 {
		t.Errorf("after steady answer: adds=%d removed=%d notified=%d, want no changes",
			ri.adds, len(ri.removed), len(notified))
	}
}

// While the reclaim does not stick (Add keeps failing), repeated answers
// retry the install but notify only once per episode; RemoveAll re-arms
// it while the foreign client still holds the address.
func TestEnsureRouteReclaimNotifiesOncePerEpisode(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	foreign := [4]byte{192, 168, 176, 1}
	ri := newFakeInstaller()
	ri.routes[addrA] = foreign
	ri.addErr = errors.New("add refused")

	var notified []string
	notify := func(addr string) { notified = append(notified, addr) }

	rs.EnsureRoute(addrA, vmGW, ri, notify)
	rs.EnsureRoute(addrA, vmGW, ri, notify)

	if len(notified) != 1 {
		t.Errorf("notify calls = %d, want 1 (once per episode)", len(notified))
	}
	if ri.adds != 2 {
		t.Errorf("Add calls = %d, want 2 (every answer retries the install)", ri.adds)
	}
	if len(ri.removed) != 1 {
		t.Errorf("Remove calls = %d, want 1 (only the first answer had a foreign route to delete)", len(ri.removed))
	}

	// RemoveAll ends the episode: with the foreign client still holding
	// the address, the next answer notifies again.
	if err := rs.RemoveAll(ri); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	ri.routes[addrA] = foreign
	rs.EnsureRoute(addrA, vmGW, ri, notify)
	if len(notified) != 2 {
		t.Errorf("notify calls after episode reset = %d, want 2", len(notified))
	}
}

// dest "default" (macOS answers with the default-route entry when nothing
// specific exists): the address is not owned by anyone, add directly
// without a Remove and without the contested notification.
func TestEnsureRouteDefaultDestAddsDirectly(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	ri := newFakeInstaller()
	ri.defaultGW = "192.168.176.1"

	var notified []string
	notify := func(addr string) { notified = append(notified, addr) }

	rs.EnsureRoute(addrA, vmGW, ri, notify)

	if ri.adds != 1 {
		t.Errorf("Add calls = %d, want 1", ri.adds)
	}
	if len(ri.removed) != 0 {
		t.Errorf("Remove calls = %v, want none for a default-dest answer", ri.removed)
	}
	if len(notified) != 0 {
		t.Errorf("notify calls = %v, want none for a default-dest answer", notified)
	}
	data, _ := os.ReadFile(rs.Path)
	if got, want := string(data), "10.15.0.64/32\n"; got != want {
		t.Errorf("state file = %q, want %q", got, want)
	}
}

func TestEnsureRouteContestedClearsAfterInstall(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	ri := newFakeInstaller()
	ri.routes[addrA] = [4]byte{10, 250, 0, 1}

	var notified []string
	notify := func(addr string) { notified = append(notified, addr) }

	rs.EnsureRoute(addrA, vmGW, ri, notify) // contested, notify #1
	if ri.adds != 1 {
		t.Fatalf("Add calls = %d, want 1", ri.adds)
	}

	// The foreign client retakes the address before the next answer: a
	// fresh episode must notify again.
	ri.routes[addrA] = [4]byte{10, 250, 0, 1}
	rs.EnsureRoute(addrA, vmGW, ri, notify)
	if len(notified) != 2 {
		t.Errorf("notify calls = %d, want 2 (a successful install resets the episode)", len(notified))
	}
}

func TestRemoveAllRemovesExactlyRecordedRoutes(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	ri := newFakeInstaller()
	unrelated := [4]byte{10, 9, 9, 9}
	ri.routes[unrelated] = [4]byte{10, 9, 9, 1} // pre-existing, never ours

	rs.EnsureRoute(addrA, vmGW, ri, nil)
	rs.EnsureRoute(addrB, vmGW, ri, nil)

	if err := rs.RemoveAll(ri); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if ri.has(addrA) || ri.has(addrB) {
		t.Error("recorded routes still present after RemoveAll")
	}
	if !ri.has(unrelated) {
		t.Error("RemoveAll touched an unrelated route it never recorded")
	}
	if got := rs.List(); len(got) != 0 {
		t.Errorf("List() after RemoveAll = %v, want empty", got)
	}
	if data, err := os.ReadFile(rs.Path); err != nil || len(data) != 0 {
		t.Errorf("state file after RemoveAll = %q (err %v), want empty", data, err)
	}
	// Idempotent: nothing recorded, a second pass must succeed quietly.
	if err := rs.RemoveAll(ri); err != nil {
		t.Errorf("second RemoveAll: %v", err)
	}
}

// The shared state file carries both this package's /32 lines and S5's
// recorded prefixes; List accepts the /32 form and the legacy plain-IP
// form and skips anything else.
func TestListParsesCIDRAndPlainLines(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	content := "10.15.0.64/32\n10.15.0.65\n10.52.0.0/24\nnot-an-ip\n\n"
	if err := os.WriteFile(rs.Path, []byte(content), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}
	got := rs.List()
	if len(got) != 2 || got[0] != addrA || got[1] != addrB {
		t.Errorf("List() = %v, want [10.15.0.64 10.15.0.65]", got)
	}
}

func TestListAndRemoveAllWithMissingOrEmptyStateFile(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")} // missing
	if got := rs.List(); len(got) != 0 {
		t.Errorf("List() on missing file = %v, want empty", got)
	}
	ri := newFakeInstaller()
	if err := rs.RemoveAll(ri); err != nil {
		t.Errorf("RemoveAll on missing state file: %v", err)
	}
	if err := os.WriteFile(rs.Path, []byte("\n"), 0o644); err != nil {
		t.Fatalf("write empty state: %v", err)
	}
	if got := rs.List(); len(got) != 0 {
		t.Errorf("List() on empty file = %v, want empty", got)
	}
	if err := rs.RemoveAll(ri); err != nil {
		t.Errorf("RemoveAll on empty state file: %v", err)
	}
}
