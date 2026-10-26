package verbs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	osignal "os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"corpvpn/internal/dnsfwd"
)

// downGrace is how long Down waits between SIGTERM and SIGKILL.
var downGrace = 5 * time.Second

// spawn is the exec seam: starts selfPath with args detached from the
// caller's process group and returns the child pid. Default re-executes
// the installed binary; tests inject a fake.
var spawn = func(selfPath string, args ...string) (int, error) {
	cmd := exec.Command(selfPath, args...)
	// Own process group: the forwarder must survive the daemon until
	// Down explicitly signals it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// The daemon's own stdout/stderr are redirected to its log file by
	// its launcher, so the child inherits them rather than opening a
	// second log path.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("spawn %s: %w", selfPath, err)
	}
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
// a live pid short-circuits. Returns the child pid.
func DNSFwdUp(selfPath, bankDomain, upstream, pidPath string) (int, error) {
	if pid, err := readPid(pidPath); err == nil && pid > 0 {
		if alive, perr := probePid(pid); perr == nil && alive {
			return pid, nil
		}
	}
	// Child argv: the main dispatch runs `dnsfwd-run` with the bank
	// domain and upstream as the following arguments.
	pid, err := spawn(selfPath, "dnsfwd-run", bankDomain, upstream)
	if err != nil {
		return 0, fmt.Errorf("dnsfwd: %w", err)
	}
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		// Without the pidfile Down could never find this child.
		_ = signal(pid, syscall.SIGKILL)
		reap(pid)
		return 0, fmt.Errorf("dnsfwd: write pidfile: %w", err)
	}
	return pid, nil
}

// DNSFwdDown stops the pid from the pidfile (SIGTERM, 5s grace, SIGKILL),
// removes the pidfile. Missing pidfile or dead pid is a no-op.
func DNSFwdDown(pidPath string) error {
	b, err := os.ReadFile(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("dnsfwd: read pidfile: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		// A pidfile only becomes corrupt when a writer crashed mid-write;
		// there is nothing to signal.
		os.Remove(pidPath)
		return nil
	}

	alive, err := probePid(pid)
	if err != nil {
		return err
	}
	if alive {
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
	}
	os.Remove(pidPath)
	return nil
}

// DNSFwdRun is the in-process entry of the child: serves UDP DNS on
// 127.0.0.1:53 until SIGINT/SIGTERM; used by main dispatch, tested
// indirectly.
func DNSFwdRun(bankDomain, upstream string) error {
	ctx, stop := osignal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	f := &dnsfwd.Forwarder{BankDomain: bankDomain, Upstream: upstream}
	return f.ServeUDP(ctx, "127.0.0.1:53")
}

// readPid returns the decimal pid stored in the pidfile.
func readPid(pidPath string) (int, error) {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
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
