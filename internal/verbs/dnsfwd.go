package verbs

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	osignal "os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"corpvpn/internal/dnsfwd"
)

// downGrace is how long Down waits between SIGTERM and SIGKILL.
var downGrace = 5 * time.Second

// spawn is the exec seam: starts selfPath with args detached from the
// caller's process group and returns the child pid. The child's
// stdout/stderr are redirected to logPath (created, appended) instead of
// inheriting the caller's pipes: a forwarder outliving the caller would
// keep the inherited pipe write end open forever and block the caller's
// Cmd.Wait. Default re-executes the installed binary; tests inject a fake.
var spawn = func(logPath, selfPath string, args ...string) (int, error) {
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, fmt.Errorf("spawn %s: open log %s: %w", selfPath, logPath, err)
	}
	cmd := exec.Command(selfPath, args...)
	// Own process group: the forwarder must survive the daemon until
	// Down explicitly signals it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return 0, fmt.Errorf("spawn %s: %w", selfPath, err)
	}
	// The child keeps its own dup of the fd; the parent's copy must
	// close or the log (and any descriptors derived from it) leak here.
	logFile.Close()
	return cmd.Process.Pid, nil
}

// signal is the signal seam; default is syscall.Kill. Signal 0 probes
// liveness.
var signal = func(pid int, sig os.Signal) error {
	return syscall.Kill(pid, sig.(syscall.Signal))
}

// reap collects the exited child so the daemon does not accumulate
// zombies; a non-child pid yields ECHILD, which we ignore.
func reap(pid int) {
	var ws syscall.WaitStatus
	_, _ = syscall.Wait4(pid, &ws, 0, nil)
}

// DNSFwdUp re-executes the installed binary as `corpvpn dnsfwd-run`
// (root, background) and writes the child pid to the pidfile. Idempotent:
// short-circuits only when the recorded child is live AND was spawned with
// the same domain/upstream (pidfile v2); a live child with different args,
// or a legacy pid-only pidfile whose args are unknown, is stopped first so
// a rotated upstream never keeps being served by the old child.
// routesPath and guestGW ride in the child argv (the forwarder installs a
// /32 per answered bank address); the pidfile keeps recording only
// domain/upstream, so staleness detection is unchanged.
// Returns the child pid.
func DNSFwdUp(selfPath, bankDomain, upstream, routesPath, guestGW, pidPath string) (int, error) {
	if e, err := readPidEntry(pidPath); err == nil && e.pid > 0 {
		alive, perr := probePid(e.pid)
		if perr == nil && alive {
			if e.domain == bankDomain && e.upstream == upstream {
				return e.pid, nil
			}
			// Reuse the Down kill path: SIGTERM, grace, SIGKILL.
			if err := stopChild(e.pid); err != nil {
				return 0, err
			}
			os.Remove(pidPath)
		}
	}
	// Child argv: the main dispatch runs `dnsfwd-run` with the bank
	// domain, upstream, the shared routes state file and the guest
	// gateway as the following arguments. The child's log lives next to
	// the pidfile, derived here so the pidPath argument stays the last
	// one.
	logPath := filepath.Join(filepath.Dir(pidPath), "dnsfwd.log")
	pid, err := spawn(logPath, selfPath, "dnsfwd-run", bankDomain, upstream, routesPath, guestGW)
	if err != nil {
		return 0, fmt.Errorf("dnsfwd: %w", err)
	}
	entry := fmt.Sprintf("%d %s %s\n", pid, bankDomain, upstream)
	if err := os.WriteFile(pidPath, []byte(entry), 0o600); err != nil {
		// Without the pidfile Down could never find this child.
		_ = signal(pid, syscall.SIGKILL)
		reap(pid)
		return 0, fmt.Errorf("dnsfwd: write pidfile: %w", err)
	}
	return pid, nil
}

// DNSFwdDown stops the child recorded in the pidfile (SIGTERM, 5s grace,
// SIGKILL), removes the pidfile. Missing pidfile or dead pid is a no-op.
func DNSFwdDown(pidPath string) error {
	b, err := os.ReadFile(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("dnsfwd: read pidfile: %w", err)
	}
	e, ok := parsePidEntry(string(b))
	if !ok {
		// A pidfile only becomes unparseable when a writer crashed
		// mid-write; there is nothing to signal.
		os.Remove(pidPath)
		return nil
	}
	if err := stopChild(e.pid); err != nil {
		return err
	}
	os.Remove(pidPath)
	return nil
}

// stopChild terminates a forwarder child: SIGTERM, downGrace wait,
// SIGKILL, then reap. Shared by Up (stale args) and Down.
func stopChild(pid int) error {
	alive, err := probePid(pid)
	if err != nil {
		return err
	}
	if !alive {
		return nil
	}
	if err := signal(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("dnsfwd: TERM pid %d: %w", pid, err)
	}
	if !waitPidGone(pid, downGrace) {
		if err := signal(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("dnsfwd: KILL pid %d: %w", pid, err)
		}
		if !waitPidGone(pid, downGrace) {
			return fmt.Errorf("dnsfwd: pid %d survived SIGKILL", pid)
		}
	}
	reap(pid)
	return nil
}

// DNSFwdRun is the in-process entry of the child: serves UDP DNS on
// 127.0.0.1:53 until SIGINT/SIGTERM and, for every forwarded A answer,
// ensures a /32 for the answered address via the guest gateway. The /32s
// are recorded in routesPath (the shared S5 recorded-routes file) so
// RemoveNet removes them. A missing or unparseable guest gateway only
// leaves the dynamic route wiring off; DNS forwarding still serves.
// Used by main dispatch, tested indirectly.
func DNSFwdRun(bankDomain, upstream, routesPath, guestGW string) error {
	ctx, stop := osignal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	f := &dnsfwd.Forwarder{BankDomain: bankDomain, Upstream: upstream}
	if gw, err := netip.ParseAddr(guestGW); err == nil && gw.Is4() && routesPath != "" {
		state := &dnsfwd.RouteState{Path: routesPath}
		ri := newRouteInstaller(gw.As4())
		f.OnAnswer = func(_ string, addr [4]byte) {
			state.EnsureRoute(addr, gw.As4(), ri, nil)
		}
	}
	return f.ServeUDP(ctx, "127.0.0.1:53")
}

// pidEntry is the parsed pidfile content. A legacy pid-only line parses
// with empty domain/upstream: the child's args are unknown, so Up must not
// short-circuit on it.
type pidEntry struct {
	pid      int
	domain   string
	upstream string
}

// parsePidEntry parses "<pid> <bankDomain> <upstream>" (v2) or "<pid>"
// (legacy). The second return is false when no pid can be read at all.
func parsePidEntry(s string) (pidEntry, bool) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return pidEntry{}, false
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return pidEntry{}, false
	}
	e := pidEntry{pid: pid}
	if len(fields) >= 3 {
		e.domain, e.upstream = fields[1], fields[2]
	}
	return e, true
}

// readPidEntry reads and parses the pidfile; read and parse errors propagate.
func readPidEntry(pidPath string) (pidEntry, error) {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return pidEntry{}, err
	}
	e, ok := parsePidEntry(string(b))
	if !ok {
		return pidEntry{}, errors.New("dnsfwd: unparseable pidfile")
	}
	return e, nil
}

// probePid reports whether pid is running. A dead pid is ESRCH; EPERM
// still means the process exists.
func probePid(pid int) (bool, error) {
	err := signal(pid, syscall.Signal(0))
	switch {
	case err == nil, errors.Is(err, syscall.EPERM):
		return true, nil
	case errors.Is(err, syscall.ESRCH):
		return false, nil
	default:
		return false, fmt.Errorf("dnsfwd: probe pid %d: %w", pid, err)
	}
}

// waitPidGone polls the pid until it disappears or the timeout expires.
func waitPidGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if alive, err := probePid(pid); err == nil && !alive {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
