package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"corpvpn/internal/authstate"
	"corpvpn/internal/daemon"
	"corpvpn/internal/failure"
	"corpvpn/internal/reconcile"
	"corpvpn/internal/verbs"
)

func TestFilterSubnets(t *testing.T) {
	tests := []struct {
		name        string
		subnets     []netip.Prefix
		excludeList string
		wantKept    []netip.Prefix
		wantRemoved []netip.Prefix
		wantErr     string
	}{
		{
			name:        "exact match removed",
			subnets:     []netip.Prefix{mustPrefix("10.0.0.0/8"), mustPrefix("172.16.0.0/12")},
			excludeList: "10.0.0.0/8",
			wantKept:    []netip.Prefix{mustPrefix("172.16.0.0/12")},
			wantRemoved: []netip.Prefix{mustPrefix("10.0.0.0/8")},
		},
		{
			name:        "contained /24 inside /16 removed",
			subnets:     []netip.Prefix{mustPrefix("10.1.2.0/24"), mustPrefix("172.16.0.0/12")},
			excludeList: "10.1.0.0/16",
			wantKept:    []netip.Prefix{mustPrefix("172.16.0.0/12")},
			wantRemoved: []netip.Prefix{mustPrefix("10.1.2.0/24")},
		},
		{
			name:        "sibling kept",
			subnets:     []netip.Prefix{mustPrefix("10.2.0.0/16")},
			excludeList: "10.1.0.0/16",
			wantKept:    []netip.Prefix{mustPrefix("10.2.0.0/16")},
			wantRemoved: nil,
		},
		{
			name:        "broader candidate kept",
			subnets:     []netip.Prefix{mustPrefix("10.0.0.0/8")},
			excludeList: "10.1.0.0/16",
			wantKept:    []netip.Prefix{mustPrefix("10.0.0.0/8")},
			wantRemoved: nil,
		},
		{
			name:        "empty exclude list is a no-op",
			subnets:     []netip.Prefix{mustPrefix("10.0.0.0/8")},
			excludeList: "",
			wantKept:    []netip.Prefix{mustPrefix("10.0.0.0/8")},
			wantRemoved: nil,
		},
		{
			name:        "malformed entry without /len aborts",
			subnets:     []netip.Prefix{mustPrefix("10.0.0.0/8")},
			excludeList: "10.0.0.0/8 not-a-cidr",
			wantErr:     "not-a-cidr",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kept, removed, err := filterSubnets(tc.subnets, tc.excludeList)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("filterSubnets = (%v, %v, %v), want error containing %q", kept, removed, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("filterSubnets = %v, want nil", err)
			}
			if !slices.Equal(kept, tc.wantKept) {
				t.Fatalf("kept = %v, want %v", kept, tc.wantKept)
			}
			if !slices.Equal(removed, tc.wantRemoved) {
				t.Fatalf("removed = %v, want %v", removed, tc.wantRemoved)
			}
		})
	}
}

// hostOpsConfig is injectable via env: CORPVPN_SUBNETS stubs the subnet
// input, CORPVPN_STATE_DIR/CORPVPN_GATEWAY keep the assembly away from
// limactl and vmIP.
func TestHostOpsConfigAppliesExclusions(t *testing.T) {
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("CORPVPN_GATEWAY", "192.168.64.5")
	t.Setenv("CORPVPN_SUBNETS", "10.1.2.0/24 172.16.0.0/12")
	t.Setenv("CORP_EXCLUDE_SUBNETS", "10.1.0.0/16")

	cfg, err := hostOpsConfig()
	if err != nil {
		t.Fatalf("hostOpsConfig = %v, want nil", err)
	}
	want := []netip.Prefix{mustPrefix("172.16.0.0/12")}
	if !slices.Equal(cfg.Subnets, want) {
		t.Fatalf("subnets = %v, want %v", cfg.Subnets, want)
	}
}

func TestHostOpsConfigAbortsOnInvalidExcludes(t *testing.T) {
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("CORPVPN_GATEWAY", "192.168.64.5")
	t.Setenv("CORPVPN_SUBNETS", "10.0.0.0/8")
	t.Setenv("CORP_EXCLUDE_SUBNETS", "10.0.0.0")

	cfg, err := hostOpsConfig()
	if err == nil || !strings.Contains(err.Error(), "invalid CIDR") {
		t.Fatalf("hostOpsConfig = (%+v, %v), want invalid-CIDR error", cfg, err)
	}
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// ---- 6.1: verb dispatch, desired/status recording, contested producer ----

// verbCall records what a dispatch seam fake saw.
type verbCall struct {
	called     bool
	iface      string
	entries    []verbs.HostsEntry
	self       string
	domain     string
	upstream   string
	routesPath string
	guestGW    string
	pidPath    string
}

// seam installs a fake into a dispatch seam var and restores it on cleanup.
func seam[A any](t *testing.T, slot *A, fake A) {
	t.Helper()
	old := *slot
	*slot = fake
	t.Cleanup(func() { *slot = old })
}

func TestCLIVerbDispatch(t *testing.T) {
	cases := []struct {
		name string
		args []string
		env  map[string]string
		// swap installs the fake seam; report renders what it saw.
		swap func(t *testing.T) func() string
		want func(t *testing.T) string
	}{
		{
			name: "root-arp-flush defaults to bridge100",
			args: []string{"root-arp-flush"},
			swap: func(t *testing.T) func() string {
				call := &verbCall{}
				seam(t, &verbFlushClonedRoutes, func(iface string) error {
					call.called = true
					call.iface = iface
					return nil
				})
				return func() string {
					if !call.called {
						return "NOT CALLED"
					}
					return call.iface
				}
			},
			want: func(*testing.T) string { return "bridge100" },
		},
		{
			name: "root-arp-flush takes iface from VM_IFACE",
			args: []string{"root-arp-flush"},
			env:  map[string]string{"VM_IFACE": "en9"},
			swap: func(t *testing.T) func() string {
				call := &verbCall{}
				seam(t, &verbFlushClonedRoutes, func(iface string) error {
					call.called = true
					call.iface = iface
					return nil
				})
				return func() string {
					if !call.called {
						return "NOT CALLED"
					}
					return call.iface
				}
			},
			want: func(*testing.T) string { return "en9" },
		},
		{
			name: "root-resolver-kick invokes the kick verb",
			args: []string{"root-resolver-kick"},
			swap: func(t *testing.T) func() string {
				call := &verbCall{}
				seam(t, &verbResolverKick, func() error {
					call.called = true
					return nil
				})
				return func() string {
					if call.called {
						return "called"
					}
					return "NOT CALLED"
				}
			},
			want: func(*testing.T) string { return "called" },
		},
		{
			name: "root-hosts-up passes the forwarder cache entries",
			args: []string{"root-hosts-up"},
			swap: func(t *testing.T) func() string {
				cache := `[{"addr":"10.15.0.64","name":"btg.wb-bank.ru"}]`
				if err := os.WriteFile(filepath.Join(os.Getenv("CORPVPN_STATE_DIR"), "hosts-cache.json"), []byte(cache), 0o644); err != nil {
					t.Fatal(err)
				}
				call := &verbCall{}
				seam(t, &verbHostsUp, func(entries []verbs.HostsEntry) error {
					call.called = true
					call.entries = entries
					return nil
				})
				return func() string {
					if !call.called {
						return "NOT CALLED"
					}
					return fmt.Sprint(call.entries)
				}
			},
			want: func(*testing.T) string { return "[{10.15.0.64 btg.wb-bank.ru}]" },
		},
		{
			name: "root-hosts-up with empty cache passes nothing",
			args: []string{"root-hosts-up"},
			swap: func(t *testing.T) func() string {
				call := &verbCall{}
				seam(t, &verbHostsUp, func(entries []verbs.HostsEntry) error {
					call.called = true
					call.entries = entries
					return nil
				})
				return func() string {
					if !call.called {
						return "NOT CALLED"
					}
					return fmt.Sprint(call.entries)
				}
			},
			want: func(*testing.T) string { return "[]" },
		},
		{
			name: "root-hosts-down invokes the down verb",
			args: []string{"root-hosts-down"},
			swap: func(t *testing.T) func() string {
				call := &verbCall{}
				seam(t, &verbHostsDown, func() error {
					call.called = true
					return nil
				})
				return func() string {
					if call.called {
						return "called"
					}
					return "NOT CALLED"
				}
			},
			want: func(*testing.T) string { return "called" },
		},
		{
			name: "root-dns-fwd up derives domain and upstream from env",
			args: []string{"root-dns-fwd", "up"},
			env: map[string]string{
				"CORP_DNS":        "10.108.67.4 10.108.67.5",
				"CORPVPN_GATEWAY": "192.168.64.5",
			},
			swap: func(t *testing.T) func() string {
				call := &verbCall{}
				seam(t, &verbDNSFwdUp, func(self, bankDomain, upstream, routesPath, guestGW, pidPath string) (int, error) {
					call.called = true
					call.self, call.domain, call.upstream = self, bankDomain, upstream
					call.routesPath, call.guestGW, call.pidPath = routesPath, guestGW, pidPath
					return 4242, nil
				})
				return func() string {
					if !call.called {
						return "NOT CALLED"
					}
					if call.self == "" {
						return "empty self path"
					}
					if call.routesPath != filepath.Join(os.Getenv("CORPVPN_STATE_DIR"), "routes") {
						return "wrong routes path " + call.routesPath
					}
					if call.guestGW != "192.168.64.5" {
						return "wrong gateway " + call.guestGW
					}
					return call.domain + " " + call.upstream + " " + filepath.Base(call.pidPath)
				}
			},
			want: func(*testing.T) string { return "wb-bank.ru 10.108.67.4:53 dnsfwd.pid" },
		},
		{
			name: "root-dns-fwd down points at the pidfile",
			args: []string{"root-dns-fwd", "down"},
			swap: func(t *testing.T) func() string {
				call := &verbCall{}
				seam(t, &verbDNSFwdDown, func(pidPath string) error {
					call.called = true
					call.pidPath = pidPath
					return nil
				})
				return func() string {
					if !call.called {
						return "NOT CALLED"
					}
					return filepath.Base(call.pidPath)
				}
			},
			want: func(*testing.T) string { return "dnsfwd.pid" },
		},
		{
			name: "daemon runs the daemon core loop",
			args: []string{"daemon"},
			swap: func(t *testing.T) func() string {
				call := &verbCall{}
				seam(t, &daemonRun, func(context.Context) error {
					call.called = true
					return nil
				})
				return func() string {
					if call.called {
						return "called"
					}
					return "NOT CALLED"
				}
			},
			want: func(*testing.T) string { return "called" },
		},
		{
			name: "dnsfwd-run receives the forwarder arguments",
			args: []string{"dnsfwd-run", "wb-bank.ru", "10.108.67.4:53", "/state/routes", "192.168.64.5"},
			swap: func(t *testing.T) func() string {
				call := &verbCall{}
				seam(t, &verbDNSFwdRun, func(bankDomain, upstream, routesPath, guestGW string) error {
					call.called = true
					call.domain, call.upstream = bankDomain, upstream
					call.routesPath, call.guestGW = routesPath, guestGW
					return nil
				})
				return func() string {
					if !call.called {
						return "NOT CALLED"
					}
					return call.domain + " " + call.upstream + " " + call.routesPath + " " + call.guestGW
				}
			},
			want: func(*testing.T) string { return "wb-bank.ru 10.108.67.4:53 /state/routes 192.168.64.5" },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			report := tc.swap(t)
			if err := dispatch(tc.args); err != nil {
				t.Fatalf("dispatch(%v) = %v, want nil", tc.args, err)
			}
			if got := report(); got != tc.want(t) {
				t.Fatalf("verb saw %q, want %q", got, tc.want(t))
			}
		})
	}
}

func TestCLIRootNetUpEmptyOverrideMeansNoSubnets(t *testing.T) {
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("CORPVPN_GATEWAY", "192.168.64.5")
	t.Setenv("CORPVPN_SUBNETS", "")
	t.Setenv("CORP_SUBNETS", "")

	cfg, err := hostOpsConfig()
	if err != nil {
		t.Fatalf("hostOpsConfig = %v, want nil (the bulk derivation fallback is gone)", err)
	}
	if len(cfg.Subnets) != 0 {
		t.Fatalf("subnets = %v, want none -- an empty kept-set must stay empty", cfg.Subnets)
	}
}

func TestCLIStatusRendersDaemonStatusFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CORPVPN_STATE_DIR", dir)

	out := captureHealLog(t, func() { printDaemonStatus() })
	if !strings.Contains(out, "daemon: нет статуса") {
		t.Fatalf("output = %q, want the missing-status fallback", out)
	}

	st := daemon.Status{
		Desired:   daemon.Up,
		Steps:     map[string]string{"S4 tunnel": "ok", "S5 host-net": "ok"},
		Probe:     "ok",
		Contested: []string{"10.52.0.7"},
		UpdatedAt: time.Now(),
	}
	if err := daemon.WriteStatus(filepath.Join(dir, statusFile), st); err != nil {
		t.Fatal(err)
	}
	out = captureHealLog(t, func() { printDaemonStatus() })
	for _, want := range []string{"желаемый статус: up", "S4 tunnel:", "S5 host-net:", "probe:", "contested:", "10.52.0.7"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output = %q, want it to contain %q", out, want)
		}
	}
}

func TestCLIRecordsDesiredAndContested(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CORPVPN_STATE_DIR", dir)

	recordDesired(daemon.Up)
	got, err := daemon.ReadDesired(filepath.Join(dir, desiredFile))
	if err != nil || got != daemon.Up {
		t.Fatalf("ReadDesired = (%s, %v), want up", got, err)
	}

	// No status file yet: the contested producer creates one and carries
	// the recorded desired state over.
	recordContested([]string{"10.52.0.7"})
	st, err := daemon.ReadStatus(filepath.Join(dir, statusFile))
	if err != nil {
		t.Fatalf("ReadStatus: %v", err)
	}
	if !slices.Equal(st.Contested, []string{"10.52.0.7"}) {
		t.Fatalf("contested = %v, want [10.52.0.7]", st.Contested)
	}
	if st.Desired != daemon.Up {
		t.Fatalf("desired = %q, want up", st.Desired)
	}

	// An existing status keeps its steps; the contested list is replaced
	// by what the latest reconcile saw.
	st.Steps = map[string]string{"S6 end-to-end": "ok"}
	if err := daemon.WriteStatus(filepath.Join(dir, statusFile), st); err != nil {
		t.Fatal(err)
	}
	recordContested(nil)
	st, err = daemon.ReadStatus(filepath.Join(dir, statusFile))
	if err != nil {
		t.Fatalf("ReadStatus: %v", err)
	}
	if len(st.Contested) != 0 {
		t.Fatalf("contested = %v, want cleared by the fresh reconcile", st.Contested)
	}
	if _, ok := st.Steps["S6 end-to-end"]; !ok {
		t.Fatalf("steps = %v, want the pre-existing step kept", st.Steps)
	}
}

// ---- Do 8: daemon Probe/Reconcile production wiring ----

type stepReport struct {
	name string
	err  error
}

func reportCollector() (func(string, error), *[]stepReport) {
	var got []stepReport
	return func(name string, err error) { got = append(got, stepReport{name, err}) }, &got
}

// fakeStep builds a named step with injectable ensure/verify; nil funcs pass.
func fakeStep(name string, ensure, verify func() error) reconcile.Step {
	return reconcile.Step{
		Name: name,
		Ensure: func(context.Context) error {
			if ensure != nil {
				return ensure()
			}
			return nil
		},
		Verify: func(context.Context) error {
			if verify != nil {
				return verify()
			}
			return nil
		},
	}
}

func TestCLIProbeConfigFollowsBankContract(t *testing.T) {
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("CHECK_HOSTS", "wiki.corp.example") // dead contract: must be ignored

	domain, host, err := probeConfig()
	if err != nil {
		t.Fatalf("probeConfig = %v, want nil (defaults apply)", err)
	}
	if domain != "wb-bank.ru" || host != "btg.wb-bank.ru" {
		t.Fatalf("probeConfig = (%q, %q), want the bank-config defaults", domain, host)
	}

	t.Setenv("BANK_DOMAIN", "corp.example")
	t.Setenv("BANK_PROBE_HOST", "wiki.corp.example")
	domain, host, err = probeConfig()
	if err != nil {
		t.Fatalf("probeConfig = %v, want nil", err)
	}
	if domain != "corp.example" || host != "wiki.corp.example" {
		t.Fatalf("probeConfig = (%q, %q), want the overridden bank config", domain, host)
	}
}

func TestCLIDaemonProbeBadConfigIsRed(t *testing.T) {
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("BANK_DOMAIN", "-bad-")
	if err := daemonProbe(context.Background()); err == nil {
		t.Fatal("daemonProbe = nil, want an error (invalid bank config must probe red, not skip)")
	}
}

func TestCLICheckRejectsInvalidBankConfig(t *testing.T) {
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("BANK_DOMAIN", "not a domain")
	if err := cmdCheck(); err == nil {
		t.Fatal("cmdCheck = nil, want the bank-config error before any probing")
	}
}

func TestCLIDaemonReconcile(t *testing.T) {
	t.Run("parked reports auth and builds no steps", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CORPVPN_STATE_DIR", dir)
		for i := 0; i < authstate.MaxConsecutive; i++ {
			if _, err := authstate.RecordAuthFailure(dir); err != nil {
				t.Fatal(err)
			}
		}
		built := swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) {
			return []reconcile.Step{{Name: "S4 tunnel"}}, nil
		})
		report, got := reportCollector()
		if err := daemonReconcile(context.Background(), report); err != nil {
			t.Fatalf("daemonReconcile = %v, want nil (parked is not retryable)", err)
		}
		if *built {
			t.Fatal("parked pass must not build steps (ADR-005)")
		}
		if len(*got) != 1 || (*got)[0].name != "auth" || (*got)[0].err == nil {
			t.Fatalf("reports = %+v, want exactly one (\"auth\", err)", *got)
		}
	})

	t.Run("step builder failure reports env", func(t *testing.T) {
		t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
		envErr := errors.New("S6 probe needs CORP_DOMAINS and CHECK_HOSTS in .env")
		swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) { return nil, envErr })
		report, got := reportCollector()
		if err := daemonReconcile(context.Background(), report); err != nil {
			t.Fatalf("daemonReconcile = %v, want nil", err)
		}
		if len(*got) != 1 || (*got)[0].name != "env" || !errors.Is((*got)[0].err, envErr) {
			t.Fatalf("reports = %+v, want exactly one (\"env\", envErr)", *got)
		}
	})

	t.Run("healthy pass reports each step ok and resets the breaker", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CORPVPN_STATE_DIR", dir)
		if _, err := authstate.RecordAuthFailure(dir); err != nil { // arm, not parked
			t.Fatal(err)
		}
		swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) {
			return []reconcile.Step{fakeStep("S1 vm", nil, nil), fakeStep("S4 tunnel", nil, nil)}, nil
		})
		report, got := reportCollector()
		if err := daemonReconcile(context.Background(), report); err != nil {
			t.Fatalf("daemonReconcile = %v, want nil", err)
		}
		if len(*got) != 2 {
			t.Fatalf("reports = %+v, want one verdict per step", *got)
		}
		for _, r := range *got {
			if r.err != nil {
				t.Fatalf("step %s reported %v, want ok", r.name, r.err)
			}
		}
		if st, err := authstate.Load(dir); err != nil || st.Consecutive != 0 || st.Parked {
			t.Fatalf("auth state = (%+v, %v), want reset by RecordAuthSuccess", st, err)
		}
	})

	t.Run("cascade repairs from the first broken step and records the whole picture", func(t *testing.T) {
		t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
		fixed := false
		var ensured []string
		steps := []reconcile.Step{
			fakeStep("A",
				func() error { ensured = append(ensured, "A"); fixed = true; return nil },
				func() error {
					if !fixed {
						return errors.New("A blackholed")
					}
					return nil
				}),
			fakeStep("B", func() error { ensured = append(ensured, "B"); return nil }, nil),
			fakeStep("C", func() error { ensured = append(ensured, "C"); return nil }, nil),
		}
		swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) { return steps, nil })
		report, got := reportCollector()
		if err := daemonReconcile(context.Background(), report); err != nil {
			t.Fatalf("daemonReconcile = %v, want nil after the repair", err)
		}
		// Verify-everything-first: B and C are reported ok even though A is broken.
		if len(*got) < 3 || (*got)[0].name != "A" || (*got)[0].err == nil ||
			(*got)[1].name != "B" || (*got)[1].err != nil ||
			(*got)[2].name != "C" || (*got)[2].err != nil {
			t.Fatalf("first reports = %+v, want A fail, B ok, C ok", *got)
		}
		// The cascade starts at A and repairs through C.
		if !slices.Equal(ensured, []string{"A", "B", "C"}) {
			t.Fatalf("ensured = %v, want [A B C]", ensured)
		}
	})

	t.Run("cascade stops at the first error", func(t *testing.T) {
		t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
		var ensured []string
		steps := []reconcile.Step{
			fakeStep("A",
				func() error { return errors.New("A ensure failed") },
				func() error { return errors.New("A blackholed") }),
			fakeStep("B", func() error { ensured = append(ensured, "B"); return nil }, nil),
		}
		swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) { return steps, nil })
		report, got := reportCollector()
		if err := daemonReconcile(context.Background(), report); err == nil {
			t.Fatal("daemonReconcile = nil, want the cascade error")
		}
		if slices.Contains(ensured, "B") {
			t.Fatal("cascade must stop at the first error, not ensure B")
		}
		last := (*got)[len(*got)-1]
		if last.name != "A" || last.err == nil || !strings.Contains(last.err.Error(), "A ensure failed") {
			t.Fatalf("last report = %+v, want the A ensure error", last)
		}
	})

	t.Run("auth failure in the cascade records the breaker", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CORPVPN_STATE_DIR", dir)
		authErr := fmt.Errorf("S4 tunnel: %w", failure.ErrAuth)
		steps := []reconcile.Step{
			fakeStep("S4 tunnel", func() error { return authErr }, func() error { return authErr }),
		}
		swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) { return steps, nil })
		report, got := reportCollector()

		if err := daemonReconcile(context.Background(), report); !errors.Is(err, failure.ErrAuth) {
			t.Fatalf("daemonReconcile = %v, want the auth error", err)
		}
		if st, err := authstate.Load(dir); err != nil || st.Consecutive != 1 {
			t.Fatalf("auth state after pass 1 = (%+v, %v), want consecutive=1", st, err)
		}
		// A second auth failure must trip the breaker.
		if err := daemonReconcile(context.Background(), report); !errors.Is(err, failure.ErrAuth) {
			t.Fatalf("daemonReconcile pass 2 = %v, want the auth error", err)
		}
		if st, err := authstate.Load(dir); err != nil || !st.Parked {
			t.Fatalf("auth state after pass 2 = (%+v, %v), want parked", st, err)
		}
		_ = got
	})
}

// ---- 6.4: down path stops the forwarder, wedge watcher driven per tick ----

func TestCLIHostNetDownStopsForwarder(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name      string
		reached   bool
		sudoErr   error
		pairErr   error
		routeDown func() error
		wantPair  bool
		wantErr   bool
	}{
		{
			name:      "sudo grant path pairs the forwarder stop",
			reached:   true,
			routeDown: func() error { t.Fatal("fallback must not run"); return nil },
			wantPair:  true,
		},
		{
			name:      "interactive fallback pairs the forwarder stop too",
			reached:   false,
			sudoErr:   errors.New("exit status 1"),
			routeDown: func() error { return nil },
			wantPair:  true,
		},
		{
			name:      "root-net-down failure leaves the pairing out",
			reached:   true,
			sudoErr:   errors.New("net-down failed"),
			routeDown: func() error { t.Fatal("fallback must not run"); return nil },
			wantErr:   true,
		},
		{
			name:      "pairing failure is a warning, not a down failure",
			reached:   true,
			pairErr:   errors.New("pidfile gone"),
			routeDown: func() error { t.Fatal("fallback must not run"); return nil },
			wantPair:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			paired := 0
			seam(t, &sudoDNSFwdDown, func(context.Context) error {
				paired++
				return tc.pairErr
			})
			err := hostNetDown(ctx,
				func(context.Context, []string, []string) (bool, error) { return tc.reached, tc.sudoErr },
				tc.routeDown)
			if (err != nil) != tc.wantErr {
				t.Fatalf("hostNetDown = %v, wantErr=%v", err, tc.wantErr)
			}
			want := 0
			if tc.wantPair {
				want = 1
			}
			if paired != want {
				t.Fatalf("forwarder stop ran %d times, want %d", paired, want)
			}
		})
	}
}

// ---- 6.4 fix round 8: root-dns-fwd up always restarts the forwarder ----

// DNSFwdUp short-circuits on a live child with matching args, so a
// hung-but-alive forwarder survived every ensure forever. The root verb
// now pairs down before up: every `root-dns-fwd up` must yield a freshly
// started child. DNSFwdUp's own idempotency contract stays for direct
// callers and is not exercised here.
func TestCLIRootDNSFwdUpRestartsForwarder(t *testing.T) {
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("CORP_DNS", "10.108.67.4 10.108.67.5")
	t.Setenv("CORPVPN_GATEWAY", "192.168.64.5")

	var order []string
	var downPid, upPid, upSelf, upDomain, upUpstream, upRoutes, upGW string
	seam(t, &verbDNSFwdDown, func(pidPath string) error {
		order = append(order, "down")
		downPid = pidPath
		return nil
	})
	seam(t, &verbDNSFwdUp, func(self, bankDomain, upstream, routesPath, guestGW, pidPath string) (int, error) {
		order = append(order, "up")
		upSelf, upDomain, upUpstream = self, bankDomain, upstream
		upRoutes, upGW, upPid = routesPath, guestGW, pidPath
		return 4242, nil
	})

	if err := dispatch([]string{"root-dns-fwd", "up"}); err != nil {
		t.Fatalf("dispatch root-dns-fwd up = %v, want nil", err)
	}
	if !slices.Equal(order, []string{"down", "up"}) {
		t.Fatalf("call order = %v, want down before up (every ensure restarts)", order)
	}
	if downPid == "" || downPid != upPid {
		t.Fatalf("down pidfile %q, up pidfile %q, want the same dnsfwd.pid", downPid, upPid)
	}
	if upSelf == "" {
		t.Fatal("up must receive the executable path")
	}
	if upDomain != "wb-bank.ru" || upUpstream != "10.108.67.4:53" {
		t.Fatalf("up args = %s %s, want wb-bank.ru 10.108.67.4:53 (first CORP_DNS)", upDomain, upUpstream)
	}
	if upRoutes != filepath.Join(os.Getenv("CORPVPN_STATE_DIR"), "routes") {
		t.Fatalf("up routesPath = %q, want the S5 recorded-routes file", upRoutes)
	}
	if upGW != "192.168.64.5" {
		t.Fatalf("up gateway = %q, want CORPVPN_GATEWAY", upGW)
	}
}

// A failed stop (e.g. a pid surviving SIGKILL) is a warning, never a reason
// to skip the start: no forwarder at all is worse than a stuck one, and the
// S5/S6 probes surface the aftermath.
func TestCLIRootDNSFwdUpProceedsAfterDownError(t *testing.T) {
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("CORP_DNS", "10.108.67.4")
	t.Setenv("CORPVPN_GATEWAY", "192.168.64.5")

	upRan := false
	seam(t, &verbDNSFwdDown, func(string) error { return errors.New("pid survived SIGKILL") })
	seam(t, &verbDNSFwdUp, func(string, string, string, string, string, string) (int, error) {
		upRan = true
		return 4242, nil
	})
	if err := dispatch([]string{"root-dns-fwd", "up"}); err != nil {
		t.Fatalf("dispatch root-dns-fwd up = %v, want nil (down failure is a warning)", err)
	}
	if !upRan {
		t.Fatal("up must run even when the paired down fails")
	}
}

func TestWedgeDriverTicksIncreaseAndCarryCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CORPVPN_STATE_DIR", dir)
	cache := `[{"addr":"10.15.0.64","name":"btg.wb-bank.ru"}]`
	if err := os.WriteFile(filepath.Join(dir, "hosts-cache.json"), []byte(cache), 0o644); err != nil {
		t.Fatal(err)
	}

	var cycles []int
	var caches [][]verbs.HostsEntry
	wd := &wedgeDriver{cycle: func(_ context.Context, n int, c []verbs.HostsEntry) {
		cycles = append(cycles, n)
		caches = append(caches, c)
	}}
	wd.eachTick(context.Background())
	wd.eachTick(context.Background())

	if !slices.Equal(cycles, []int{1, 2}) {
		t.Fatalf("cycle numbers = %v, want [1 2] (starts at 1, grows per tick)", cycles)
	}
	want := []verbs.HostsEntry{{Addr: "10.15.0.64", Name: "btg.wb-bank.ru"}}
	if len(caches) != 2 || !reflect.DeepEqual(caches[0], want) || !reflect.DeepEqual(caches[1], want) {
		t.Fatalf("caches = %v, want the forwarder cache entries on every tick", caches)
	}
}

func TestWedgeDriverProductionWiring(t *testing.T) {
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("BANK_PROBE_HOST", "wiki.corp.example")

	wd := newWedgeDriver()
	if wd.watcher == nil {
		t.Fatal("newWedgeDriver returned no watcher")
	}
	if wd.watcher.TestHost != "wiki.corp.example" {
		t.Fatalf("TestHost = %q, want the bank config probe host", wd.watcher.TestHost)
	}
	if wd.watcher.ForwarderAddr != "127.0.0.1" {
		t.Fatalf("ForwarderAddr = %q, want 127.0.0.1", wd.watcher.ForwarderAddr)
	}
	for name, f := range map[string]any{
		"ScopedLookup":     wd.watcher.ScopedLookup,
		"ForwarderAnswers": wd.watcher.ForwarderAnswers,
		"Kick":             wd.watcher.Kick,
		"HostsUp":          wd.watcher.HostsUp,
		"Notify":           wd.watcher.Notify,
	} {
		if f == nil {
			t.Fatalf("%s must be wired for production, got nil", name)
		}
	}
}
