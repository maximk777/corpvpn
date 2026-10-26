package verbs

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// installSeams swaps the spawn/signal seams and the down grace for fakes,
// restoring the originals on cleanup. A nil spawnFn or sigFn fails the test
// if the code under test dares to call it.
func installSeams(t *testing.T, spawnFn func(string, ...string) (int, error), sigFn func(int, os.Signal) error, grace time.Duration) {
	t.Helper()
	oldSpawn, oldSignal, oldGrace := spawn, signal, downGrace
	t.Cleanup(func() { spawn, signal, downGrace = oldSpawn, oldSignal, oldGrace })
	spawn = func(selfPath string, args ...string) (int, error) {
		if spawnFn == nil {
			t.Errorf("unexpected spawn %q %v", selfPath, args)
			return 0, errors.New("unexpected spawn")
		}
		return spawnFn(selfPath, args...)
	}
	signal = func(pid int, sig os.Signal) error {
		if sigFn == nil {
			t.Errorf("unexpected signal %d %v", pid, sig)
			return errors.New("unexpected signal")
		}
		return sigFn(pid, sig)
	}
	downGrace = grace
}

func writePidFile(t *testing.T, path string, pid int) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatalf("write pidfile: %v", err)
	}
}

func TestDNSFwdUp(t *testing.T) {
	t.Run("up writes pidfile and returns pid", func(t *testing.T) {
		pidPath := filepath.Join(t.TempDir(), "dnsfwd.pid")
		var gotSelf string
		var gotArgs []string
		installSeams(t, func(selfPath string, args ...string) (int, error) {
			gotSelf = selfPath
			gotArgs = args
			return 4242, nil
		}, nil, time.Second)

		pid, err := DNSFwdUp("/usr/local/bin/corpvpn", "wb-bank.ru", "10.108.67.4:53", pidPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pid != 4242 {
			t.Fatalf("pid = %d, want 4242", pid)
		}
		if gotSelf != "/usr/local/bin/corpvpn" {
			t.Errorf("selfPath = %q", gotSelf)
		}
		if want := []string{"dnsfwd-run", "wb-bank.ru", "10.108.67.4:53"}; !reflect.DeepEqual(gotArgs, want) {
			t.Errorf("args = %v, want %v", gotArgs, want)
		}
		b, err := os.ReadFile(pidPath)
		if err != nil {
			t.Fatalf("read pidfile: %v", err)
		}
		if got, want := string(b), "4242\n"; got != want {
			t.Errorf("pidfile = %q, want %q", got, want)
		}
	})

	t.Run("up with live pid is a no-op returning same pid", func(t *testing.T) {
		pidPath := filepath.Join(t.TempDir(), "dnsfwd.pid")
		writePidFile(t, pidPath, 5150)
		installSeams(t, func(string, ...string) (int, error) {
			return 0, errors.New("must not spawn over a live pid")
		}, func(pid int, sig os.Signal) error {
			if pid != 5150 {
				t.Errorf("probed pid %d, want 5150", pid)
			}
			if !isSignalZero(sig) {
				t.Errorf("probe used %v, want signal 0", sig)
			}
			return nil // alive
		}, time.Second)

		pid, err := DNSFwdUp("corpvpn", "wb-bank.ru", "10.108.67.4:53", pidPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pid != 5150 {
			t.Fatalf("pid = %d, want 5150", pid)
		}
		b, err := os.ReadFile(pidPath)
		if err != nil {
			t.Fatalf("read pidfile: %v", err)
		}
		if got, want := string(b), "5150\n"; got != want {
			t.Errorf("pidfile = %q, want %q untouched", got, want)
		}
	})

	t.Run("up respawns over a stale pidfile", func(t *testing.T) {
		pidPath := filepath.Join(t.TempDir(), "dnsfwd.pid")
		writePidFile(t, pidPath, 999)
		installSeams(t, func(string, ...string) (int, error) {
			return 4242, nil
		}, func(int, os.Signal) error {
			return syscall.ESRCH // dead
		}, time.Second)

		pid, err := DNSFwdUp("corpvpn", "wb-bank.ru", "10.108.67.4:53", pidPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pid != 4242 {
			t.Fatalf("pid = %d, want 4242", pid)
		}
		b, _ := os.ReadFile(pidPath)
		if got, want := string(b), "4242\n"; got != want {
			t.Errorf("pidfile = %q, want %q", got, want)
		}
	})
}

func isSignalZero(sig os.Signal) bool {
	s, ok := sig.(syscall.Signal)
	return ok && s == 0
}

func TestDNSFwdDown(t *testing.T) {
	t.Run("down kills and removes pidfile", func(t *testing.T) {
		pidPath := filepath.Join(t.TempDir(), "dnsfwd.pid")
		writePidFile(t, pidPath, 777)
		terminated := false
		var sigs []os.Signal
		installSeams(t, nil, func(pid int, sig os.Signal) error {
			if pid != 777 {
				t.Errorf("signalled pid %d, want 777", pid)
			}
			if isSignalZero(sig) {
				if !terminated {
					return nil // alive until TERM lands
				}
				return syscall.ESRCH
			}
			sigs = append(sigs, sig)
			if sig == syscall.SIGTERM {
				terminated = true
			}
			return nil
		}, 30*time.Millisecond)

		if err := DNSFwdDown(pidPath); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sigs) != 1 || sigs[0] != syscall.SIGTERM {
			t.Errorf("signals = %v, want exactly one SIGTERM", sigs)
		}
		if _, err := os.Stat(pidPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pidfile still present: %v", err)
		}
	})

	t.Run("down escalates to SIGKILL after the grace", func(t *testing.T) {
		pidPath := filepath.Join(t.TempDir(), "dnsfwd.pid")
		writePidFile(t, pidPath, 777)
		var sigs []os.Signal
		killed := false
		installSeams(t, nil, func(pid int, sig os.Signal) error {
			if isSignalZero(sig) {
				if killed {
					return syscall.ESRCH
				}
				return nil // TERM ignored, alive
			}
			sigs = append(sigs, sig)
			if sig == syscall.SIGKILL {
				killed = true
			}
			return nil
		}, 30*time.Millisecond)

		if err := DNSFwdDown(pidPath); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sigs) != 2 || sigs[0] != syscall.SIGTERM || sigs[1] != syscall.SIGKILL {
			t.Errorf("signals = %v, want SIGTERM then SIGKILL", sigs)
		}
		if _, err := os.Stat(pidPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pidfile still present: %v", err)
		}
	})

	t.Run("down with missing pidfile is nil", func(t *testing.T) {
		pidPath := filepath.Join(t.TempDir(), "dnsfwd.pid")
		installSeams(t, nil, nil, time.Second)
		if err := DNSFwdDown(pidPath); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("down with dead pid is nil and clears the pidfile", func(t *testing.T) {
		pidPath := filepath.Join(t.TempDir(), "dnsfwd.pid")
		writePidFile(t, pidPath, 999)
		var sigs []os.Signal
		installSeams(t, nil, func(pid int, sig os.Signal) error {
			if !isSignalZero(sig) {
				sigs = append(sigs, sig)
			}
			return syscall.ESRCH
		}, time.Second)

		if err := DNSFwdDown(pidPath); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sigs) != 0 {
			t.Errorf("signals = %v, want none", sigs)
		}
		if _, err := os.Stat(pidPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pidfile still present: %v", err)
		}
	})

	t.Run("down with a corrupt pidfile is nil and clears it", func(t *testing.T) {
		pidPath := filepath.Join(t.TempDir(), "dnsfwd.pid")
		if err := os.WriteFile(pidPath, []byte("not-a-pid"), 0o600); err != nil {
			t.Fatalf("write pidfile: %v", err)
		}
		installSeams(t, nil, nil, time.Second)
		if err := DNSFwdDown(pidPath); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(pidPath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("pidfile still present: %v", err)
		}
	})
}
