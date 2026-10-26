package dnsfwd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// fakeInstaller is an in-memory RouteInstaller. routes maps an address to
// the gateway its /32 points at; an absent address means "no route".
type fakeInstaller struct {
	routes  map[[4]byte][4]byte
	adds    int
	removed [][4]byte
}

func newFakeInstaller() *fakeInstaller {
	return &fakeInstaller{routes: make(map[[4]byte][4]byte)}
}

func (f *fakeInstaller) Add(addr, gw [4]byte) (bool, error) {
	f.adds++
	f.routes[addr] = gw
	return true, nil
}

func (f *fakeInstaller) GatewayOf(addr [4]byte) (string, error) {
	if gw, ok := f.routes[addr]; ok {
		return ipString(gw), nil
	}
	return "", fmt.Errorf("no route to %s", ipString(addr))
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
	if got, want := string(data), "10.15.0.64\n"; got != want {
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
	if got, want := string(data), "10.15.0.64\n"; got != want {
		t.Errorf("state file = %q, want %q (repeated answer must not duplicate)", got, want)
	}
}

func TestEnsureRouteForeignGatewayIsContested(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	foreignGW := [4]byte{10, 250, 0, 1}
	ri := newFakeInstaller()
	ri.routes[addrA] = foreignGW // a foreign client owns this address

	var notified []string
	notify := func(addr string) { notified = append(notified, addr) }

	rs.EnsureRoute(addrA, vmGW, ri, notify)
	rs.EnsureRoute(addrA, vmGW, ri, notify)

	if ri.adds != 0 {
		t.Errorf("Add calls = %d, want 0 for a contested address", ri.adds)
	}
	if len(notified) != 1 || notified[0] != "10.15.0.64" {
		t.Errorf("notify calls = %v, want exactly once with 10.15.0.64", notified)
	}
	if _, err := os.Stat(rs.Path); err == nil {
		t.Error("state file created for a contested address, want none")
	}

	// RemoveAll ends the episode: the next contested answer notifies again.
	if err := rs.RemoveAll(ri); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	rs.EnsureRoute(addrA, vmGW, ri, notify)
	if len(notified) != 2 {
		t.Errorf("notify calls after episode reset = %d, want 2", len(notified))
	}
}

func TestEnsureRouteContestedClearsAfterInstall(t *testing.T) {
	rs := &RouteState{Path: filepath.Join(t.TempDir(), "routes")}
	foreignGW := [4]byte{10, 250, 0, 1}
	ri := newFakeInstaller()
	ri.routes[addrA] = foreignGW

	var notified []string
	notify := func(addr string) { notified = append(notified, addr) }

	rs.EnsureRoute(addrA, vmGW, ri, notify) // contested, notify #1

	// The foreign route vanished before the next answer: the address is
	// installable now, which must clear the contested episode.
	delete(ri.routes, addrA)
	rs.EnsureRoute(addrA, vmGW, ri, notify)
	if ri.adds != 1 {
		t.Fatalf("Add calls = %d, want 1", ri.adds)
	}

	// Foreign ownership returns: a fresh episode must notify again.
	ri.routes[addrA] = foreignGW
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
