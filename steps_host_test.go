// steps_host_test.go covers S5/S6 with fakes and the root-net config assembly.
package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"corpvpn/internal/hostops"
	"corpvpn/internal/reconcile"
)

// sudoFake is an injectable runSudo: it records every invocation (argv and
// environment) and replays a scripted outcome.
type sudoFake struct {
	calls   int
	args    [][]string
	envs    [][]string
	reached bool
	err     error
}

func (f *sudoFake) run(_ context.Context, args []string, environ []string) (bool, error) {
	f.calls++
	f.args = append(f.args, args)
	f.envs = append(f.envs, environ)
	return f.reached, f.err
}

// hostExecFake is an injectable host exec: it records every invocation and
// answers from scripted output keyed by the joined argv. seq serves
// progressively per key (the route get before an add and the verify get after
// it need different answers), falling back to out.
type hostExecFake struct {
	calls []string
	out   map[string]string
	seq   map[string][]string
	seen  map[string]int
	err   error
}

func (f *hostExecFake) run(_ context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.err != nil {
		return "", f.err
	}
	if seq := f.seq[call]; len(seq) > 0 {
		i := f.seen[call]
		f.seen[call] = i + 1
		if i < len(seq) {
			return seq[i], nil
		}
		return seq[len(seq)-1], nil
	}
	return f.out[call], nil
}

// testBankAddr is the healthy bank address the S5 tests route; testExcludedAddr
// sits inside testCorpEnv's excluded prefix (10.20.0.0/16) and must be skipped.
var (
	testBankAddr     = netip.MustParseAddr("10.15.0.82")
	testExcludedAddr = netip.MustParseAddr("10.20.0.5")
)

// withBankAddrs injects the S5 address source and silences the contested
// notification (collecting the messages when msgs is non-nil), and resets
// the contested episode state around the test.
func withBankAddrs(t *testing.T, msgs *[]string, addrs ...netip.Addr) {
	t.Helper()
	oldAddrs := bankAddrsFn
	bankAddrsFn = func(context.Context, corpEnv) ([]netip.Addr, error) { return addrs, nil }
	t.Cleanup(func() { bankAddrsFn = oldAddrs })

	oldNotify := contestedNotifyFn
	contestedNotifyFn = func(m string) {
		if msgs != nil {
			*msgs = append(*msgs, m)
		}
	}
	t.Cleanup(func() { contestedNotifyFn = oldNotify })

	resetEpisode := func() {
		contestedEpisode.Range(func(k, _ any) bool {
			contestedEpisode.Delete(k)
			return true
		})
	}
	resetEpisode()
	t.Cleanup(resetEpisode)
}

// testCorpEnv is a corpEnv with one excluded prefix (10.20.0.0/16) that must
// never leak past the per-address skip.
func testCorpEnv(t *testing.T) *corpEnv {
	t.Helper()
	return &corpEnv{
		Excluded:    []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Gateway:     "192.168.64.2",
		CorpDomains: []string{"corp.example"},
		OVPNDomains: []string{"stage.example"},
		CorpDNS:     []string{"10.10.0.1"},
		CheckHost:   "wiki.corp.example",
		StateDir:    t.TempDir(),
	}
}

// s5HealthyDeps returns deps whose S5 verify passes: the resolver files (in a
// temp dir standing in for /etc/resolver) are staged and route -n get for the
// bank address resolves via the VM gateway.
func s5HealthyDeps(t *testing.T, env *corpEnv) stepDeps {
	t.Helper()
	dir := t.TempDir()
	for _, dom := range env.CorpDomains {
		if err := os.WriteFile(filepath.Join(dir, dom), []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env.StateDir = dir
	return stepDeps{
		runHost: (&hostExecFake{out: map[string]string{
			"route -n get " + testBankAddr.String(): "   route to: 10.15.0.82\ndestination: 10.15.0.82\n    gateway: 192.168.64.2\n  interface: bridge100\n",
		}}).run,
		resolverDir: dir,
	}
}

func TestStepsHostBuildComposesS1ThroughS6(t *testing.T) {
	lima := healthyLima()
	dial := &dialFake{conn: pipeConn(t)}
	d, _ := healthyDeps(lima, dial)
	steps := buildSteps(d, testCorpEnv(t))

	got := make([]string, len(steps))
	for i, s := range steps {
		got[i] = s.Name
	}
	want := []string{stepVM, stepEgress, stepSocks, stepTunnel, stepHost, stepProbe}
	if !slices.Equal(got, want) {
		t.Fatalf("buildSteps = %v, want %v", got, want)
	}
}

func TestStepsHostS5EnsurePassesBankAddrsViaEnv(t *testing.T) {
	env := testCorpEnv(t)
	withBankAddrs(t, nil, testBankAddr, testExcludedAddr)
	sudo := &sudoFake{reached: true}
	d := stepDeps{
		runSudo:  sudo.run,
		stdinTTY: func() bool { return false },
	}
	// A stale inherited override must be replaced, not duplicated.
	t.Setenv("CORPVPN_SUBNETS", "192.168.0.0/16")

	steps := stepsHost(d, env)
	if err := steps[0].Ensure(context.Background()); err != nil {
		t.Fatalf("ensure = %v, want nil", err)
	}
	if sudo.calls != 3 {
		t.Fatalf("sudo invoked %d times, want 3 (arp-flush, net-up, dns-fwd)", sudo.calls)
	}
	self, eerr := os.Executable()
	if eerr != nil {
		t.Fatalf("os.Executable: %v", eerr)
	}
	// Design order: arp-flush BEFORE net-up (a stale cloned host route
	// blackholes one IP even when the correct /32 exists), dns-fwd last.
	wantVerbs := []string{"root-arp-flush", "root-net-up", "root-dns-fwd up"}
	for i, want := range wantVerbs {
		joined := strings.Join(sudo.args[i], " ")
		if !strings.HasSuffix(joined, " "+want) {
			t.Fatalf("sudo call #%d argv = %v, want it to end with %q", i+1, sudo.args[i], want)
		}
	}
	if !slices.Equal(sudo.args[2], []string{"-n", self, "root-dns-fwd", "up"}) {
		t.Fatalf("dns-fwd argv = %v, want the fixed sudoers argv", sudo.args[2])
	}
	// All three calls share the same env passthrough.
	for i := 1; i < 3; i++ {
		if !slices.Equal(sudo.envs[0], sudo.envs[i]) {
			t.Fatalf("sudo call #%d env differs from the net-up env", i+1)
		}
	}

	saw := map[string]string{}
	for _, kv := range sudo.envs[0] {
		k, v, _ := strings.Cut(kv, "=")
		saw[k] = v
	}
	if got := saw["CORPVPN_SUBNETS"]; got != "10.15.0.82/32" {
		t.Fatalf("CORPVPN_SUBNETS = %q, want only the kept bank address 10.15.0.82/32", got)
	}
	if saw["CORPVPN_GATEWAY"] != env.Gateway {
		t.Fatalf("CORPVPN_GATEWAY = %q, want %q", saw["CORPVPN_GATEWAY"], env.Gateway)
	}
	if saw["CORPVPN_STATE_DIR"] != env.StateDir {
		t.Fatalf("CORPVPN_STATE_DIR = %q, want %q", saw["CORPVPN_STATE_DIR"], env.StateDir)
	}
	if saw["CORP_DOMAINS"] != "corp.example" ||
		saw["OVPN_DOMAINS"] != "stage.example" || saw["CORP_DNS"] != "10.10.0.1" {
		t.Fatalf("DNS/domain overrides incomplete: %v", saw)
	}
	for _, kv := range sudo.envs[0] {
		if strings.Contains(kv, "10.20.0.5") {
			t.Fatalf("excluded address leaked into the sudo environment: %q", kv)
		}
		if strings.HasPrefix(kv, "DNS_MODE=") {
			t.Fatalf("DNS_MODE override must be gone, got %q", kv)
		}
	}
}

func TestStepsHostS5EnsureSkipsExcludedAddrWithMessage(t *testing.T) {
	env := testCorpEnv(t)
	withBankAddrs(t, nil, testBankAddr, testExcludedAddr)
	kept := filterExcludedAddrs([]netip.Addr{testBankAddr, testExcludedAddr}, env.Excluded, func(p netip.Prefix) {
		if p.String() != "10.20.0.5/32" {
			t.Fatalf("reported prefix = %s, want 10.20.0.5/32", p)
		}
	})
	if !slices.Equal(kept, []netip.Addr{testBankAddr}) {
		t.Fatalf("kept = %v, want only %s", kept, testBankAddr)
	}
	if got := filterExcludedAddrs([]netip.Addr{testExcludedAddr}, nil, nil); len(got) != 1 {
		t.Fatalf("no excluded prefixes must keep every address, got %v", got)
	}
}

func TestStepsHostS5SudoersMissingNoTTYHintsInstall(t *testing.T) {
	env := testCorpEnv(t)
	withBankAddrs(t, nil, testBankAddr)
	sudo := &sudoFake{reached: false, err: errors.New("exit status 1")}
	routeUpCalled := false
	d := stepDeps{
		runSudo: sudo.run,
		runRouteUp: func(context.Context, []string) error {
			routeUpCalled = true
			return nil
		},
		stdinTTY: func() bool { return false },
	}

	steps := stepsHost(d, env)
	err := steps[0].Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), "sudoers rule missing: run install.sh") {
		t.Fatalf("ensure = %v, want the install.sh hint", err)
	}
	if routeUpCalled {
		t.Fatal("interactive fallback must not run without a TTY")
	}
}

func TestStepsHostS5SudoersMissingWithTTYFallsBackToScript(t *testing.T) {
	env := testCorpEnv(t)
	withBankAddrs(t, nil, testBankAddr)
	sudo := &sudoFake{reached: false, err: errors.New("exit status 1")}
	routeUpEnvs := [][]string{}
	d := stepDeps{
		runSudo: sudo.run,
		runRouteUp: func(_ context.Context, environ []string) error {
			routeUpEnvs = append(routeUpEnvs, environ)
			return nil
		},
		stdinTTY: func() bool { return true },
	}

	steps := stepsHost(d, env)
	if err := steps[0].Ensure(context.Background()); err != nil {
		t.Fatalf("ensure = %v, want nil (fallback ran)", err)
	}
	// arp-flush and net-up both ran and were both refused by sudo; dns-fwd
	// never ran because net-up did not succeed.
	if sudo.calls != 2 || len(routeUpEnvs) != 1 {
		t.Fatalf("sudo calls = %d, route-up calls = %d, want 2 and 1", sudo.calls, len(routeUpEnvs))
	}
	joined := strings.Join(routeUpEnvs[0], "\n")
	if !strings.Contains(joined, "CORPVPN_SUBNETS=10.15.0.82/32") {
		t.Fatalf("fallback env lost the bank addresses: %q", joined)
	}
}

// TestStepsHostS5ToleratesArpFlushAndFwdFailures: the design trio's extra
// calls are best-effort warnings -- arp-flush refused before net-up and a
// dns-fwd that fails after a green net-up must not fail S5 (S6 surfaces red).
func TestStepsHostS5ToleratesArpFlushAndFwdFailures(t *testing.T) {
	env := testCorpEnv(t)
	withBankAddrs(t, nil, testBankAddr)

	var calls [][]string
	outs := []struct {
		reached bool
		err     error
	}{
		{false, errors.New("sudo refused arp-flush")}, // best-effort before net-up
		{true, nil},                                   // net-up ok
		{true, errors.New("forwarder died")},          // best-effort after net-up
	}
	i := 0
	d := stepDeps{
		runSudo: func(_ context.Context, args []string, _ []string) (bool, error) {
			calls = append(calls, args)
			o := outs[i]
			i++
			return o.reached, o.err
		},
		stdinTTY: func() bool { return false },
	}

	steps := stepsHost(d, env)
	if err := steps[0].Ensure(context.Background()); err != nil {
		t.Fatalf("ensure = %v, want nil (both extra failures are best-effort)", err)
	}
	if len(calls) != 3 {
		t.Fatalf("sudo calls = %d, want 3", len(calls))
	}
}

func TestStepsHostS5EnsureFailsWhenForwarderUnreachable(t *testing.T) {
	env := testCorpEnv(t)
	old := bankAddrsFn
	bankAddrsFn = func(context.Context, corpEnv) ([]netip.Addr, error) {
		return nil, errors.New("forwarder 127.0.0.1: resolve btg.wb-bank.ru: i/o timeout")
	}
	t.Cleanup(func() { bankAddrsFn = old })
	sudo := &sudoFake{reached: true}
	d := stepDeps{
		runSudo:  sudo.run,
		stdinTTY: func() bool { return false },
	}

	steps := stepsHost(d, env)
	err := steps[0].Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), stepHost) {
		t.Fatalf("ensure = %v, want the forwarder error wrapped with %q", err, stepHost)
	}
	if sudo.calls != 0 {
		t.Fatal("root-net-up must not run without route targets")
	}
}

func TestStepsHostS5VerifyDetectsMissingResolverFile(t *testing.T) {
	env := testCorpEnv(t)
	withBankAddrs(t, nil, testBankAddr)
	env.CorpDomains = []string{"corp.example", "intranet.example"}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "corp.example"), []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := s5HealthyDeps(t, env)
	d.resolverDir = dir // one domain file staged, intranet.example deliberately missing

	steps := stepsHost(d, env)
	err := steps[0].Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "intranet.example") {
		t.Fatalf("verify = %v, want a missing-resolver error for intranet.example", err)
	}
}

func TestStepsHostS5VerifyHappyPaths(t *testing.T) {
	t.Run("resolver mode with all files present", func(t *testing.T) {
		env := testCorpEnv(t)
		withBankAddrs(t, nil, testBankAddr)
		d := s5HealthyDeps(t, env)
		steps := stepsHost(d, env)
		if err := steps[0].Verify(context.Background()); err != nil {
			t.Fatalf("verify = %v, want nil", err)
		}
	})
	t.Run("missing route fails", func(t *testing.T) {
		env := testCorpEnv(t)
		withBankAddrs(t, nil, testBankAddr)
		d := s5HealthyDeps(t, env)
		d.runHost = func(_ context.Context, name string, args ...string) (string, error) {
			return "", errors.New("route: writing to routing socket: not in table")
		}
		steps := stepsHost(d, env)
		err := steps[0].Verify(context.Background())
		if err == nil || !strings.Contains(err.Error(), "10.15.0.82") {
			t.Fatalf("verify = %v, want a missing-route error", err)
		}
	})
	t.Run("gatewayless clone fails so ensure heals it", func(t *testing.T) {
		env := testCorpEnv(t)
		withBankAddrs(t, nil, testBankAddr)
		d := s5HealthyDeps(t, env)
		d.runHost = (&hostExecFake{out: map[string]string{
			"route -n get 10.15.0.82": "   route to: 10.15.0.82\n  interface: bridge100\n",
		}}).run
		steps := stepsHost(d, env)
		err := steps[0].Verify(context.Background())
		if err == nil || !strings.Contains(err.Error(), "gatewayless clone") {
			t.Fatalf("verify = %v, want a gatewayless-clone error", err)
		}
	})
	t.Run("foreign gateway is contested, notified once per episode, not an error", func(t *testing.T) {
		env := testCorpEnv(t)
		var msgs []string
		withBankAddrs(t, &msgs, testBankAddr)
		d := s5HealthyDeps(t, env)
		d.runHost = (&hostExecFake{out: map[string]string{
			"route -n get 10.15.0.82": "   route to: 10.15.0.82\n    gateway: 192.168.1.1\n  interface: en0\n",
		}}).run
		steps := stepsHost(d, env)
		for i := 1; i <= 2; i++ {
			if err := steps[0].Verify(context.Background()); err != nil {
				t.Fatalf("verify #%d = %v, want nil (contested is never an error)", i, err)
			}
		}
		if len(msgs) != 1 {
			t.Fatalf("contested notifications = %d, want exactly one per episode (%v)", len(msgs), msgs)
		}
	})
	t.Run("recovered contested addr resets the episode", func(t *testing.T) {
		env := testCorpEnv(t)
		var msgs []string
		withBankAddrs(t, &msgs, testBankAddr)
		notifyContested(testBankAddr.String()) // contested in a previous episode

		d := s5HealthyDeps(t, env) // route is ours again
		steps := stepsHost(d, env)
		if err := steps[0].Verify(context.Background()); err != nil {
			t.Fatalf("verify = %v, want nil", err)
		}
		if _, seen := contestedEpisode.Load(testBankAddr.String()); seen {
			t.Fatal("a healthy address must leave the contested episode")
		}
		_ = msgs
	})
}

func TestStepsHostS6VerifyFailurePropagates(t *testing.T) {
	env := testCorpEnv(t)
	withBankAddrs(t, nil, testBankAddr)
	d := s5HealthyDeps(t, env) // S5 healthy so VerifyAll reaches S6
	boom := errors.New("probe: i/o timeout")
	d.check = func(context.Context, string, string) error { return boom }

	steps := stepsHost(d, env)
	err := steps[1].Verify(context.Background())
	if err == nil || !errors.Is(err, boom) || !strings.Contains(err.Error(), stepProbe) {
		t.Fatalf("verify = %v, want the probe error wrapped with %q", err, stepProbe)
	}
	broken, verr := reconcile.VerifyAll(context.Background(), steps)
	if broken != stepProbe || verr == nil {
		t.Fatalf("VerifyAll = (%q, %v), want (%q, error)", broken, verr, stepProbe)
	}
	// A repair starting exactly at S6 has nothing local to ensure; it must not panic.
	if err := steps[1].Ensure(context.Background()); err != nil {
		t.Fatalf("S6 ensure = %v, want nil", err)
	}
}

func TestStepsHostStateDirHonorsOverridesAndSudoUser(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable: %v", err)
	}
	if _, err := user.Lookup(me.Username); err != nil {
		t.Skipf("passwd lookup unavailable: %v", err)
	}
	fakeHome := t.TempDir()

	cases := []struct {
		name    string
		state   string
		sudoUsr string
		home    string
		want    string
	}{
		{"override wins over everything", "/custom/state", me.Username, fakeHome, "/custom/state"},
		{"SUDO_USER home beats $HOME", "", me.Username, fakeHome,
			filepath.Join(me.HomeDir, ".local", "state", "corpvpn")},
		{"unknown sudo user falls back to $HOME", "", "no-such-user-4b2f9", fakeHome,
			filepath.Join(fakeHome, ".local", "state", "corpvpn")},
		{"plain run uses $HOME", "", "", fakeHome,
			filepath.Join(fakeHome, ".local", "state", "corpvpn")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CORPVPN_STATE_DIR", tc.state)
			t.Setenv("SUDO_USER", tc.sudoUsr)
			t.Setenv("HOME", tc.home)
			if got := stateDir(); got != tc.want {
				t.Fatalf("stateDir() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStepsHostAssemblyHonorsRootNetOverrides(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		want    hostops.Config
		wantErr string
	}{
		{
			name: "overrides beat .env and derivation",
			env: map[string]string{
				"CORPVPN_STATE_DIR": "/state/from/env",
				"CORPVPN_GATEWAY":   "192.168.64.5",
				"CORPVPN_SUBNETS":   "10.0.0.0/8 10.9.0.0/16",
				"CORP_SUBNETS":      "172.16.0.0/12", // must be ignored
				"CORP_DOMAINS":      "corp.example",
				"OVPN_DOMAINS":      "stage.example",
				"CORP_DNS":          "10.10.0.1 10.10.0.2",
				"DNS_MODE":          "resolver",
			},
			want: hostops.Config{
				StateDir:     "/state/from/env",
				Subnets:      []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.9.0.0/16")},
				CorpDomains:  []string{"corp.example"},
				OVPNDomains:  []string{"stage.example"},
				CorpDNS:      []string{"10.10.0.1", "10.10.0.2"},
				DNSMode:      "resolver",
				IfaceGateway: "192.168.64.5",
			},
		},
		{
			name: "CORP_SUBNETS used when the override is absent",
			env: map[string]string{
				"CORPVPN_STATE_DIR": "/state",
				"CORPVPN_GATEWAY":   "192.168.64.5",
				"CORPVPN_SUBNETS":   "",
				"CORP_SUBNETS":      "172.16.0.0/12",
				"DNS_MODE":          "",
			},
			want: hostops.Config{
				StateDir:     "/state",
				Subnets:      []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")},
				DNSMode:      "primary",
				IfaceGateway: "192.168.64.5",
			},
		},
		{
			name: "invalid override prefix aborts",
			env: map[string]string{
				"CORPVPN_STATE_DIR": "/state",
				"CORPVPN_GATEWAY":   "192.168.64.5",
				"CORPVPN_SUBNETS":   "10.0.0.0",
				"CORP_SUBNETS":      "",
			},
			wantErr: "invalid CIDR",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Every override-bearing case must assemble without touching
			// limactl: vmIP/derivation would exec it and fail under the test.
			for _, k := range []string{
				"CORPVPN_STATE_DIR", "CORPVPN_GATEWAY", "CORPVPN_SUBNETS",
				"CORP_SUBNETS", "CORP_DOMAINS", "OVPN_DOMAINS", "CORP_DNS", "DNS_MODE",
			} {
				t.Setenv(k, tc.env[k])
			}
			cfg, err := hostOpsConfig()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("hostOpsConfig = (%+v, %v), want error containing %q", cfg, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("hostOpsConfig = %v, want nil", err)
			}
			if cfg.StateDir != tc.want.StateDir || cfg.IfaceGateway != tc.want.IfaceGateway ||
				cfg.DNSMode != tc.want.DNSMode {
				t.Fatalf("scalar fields = %+v, want %+v", cfg, tc.want)
			}
			if !slices.Equal(cfg.Subnets, tc.want.Subnets) {
				t.Fatalf("subnets = %v, want %v", cfg.Subnets, tc.want.Subnets)
			}
			if !slices.Equal(cfg.CorpDomains, tc.want.CorpDomains) {
				t.Fatalf("corp domains = %v, want %v", cfg.CorpDomains, tc.want.CorpDomains)
			}
			if !slices.Equal(cfg.OVPNDomains, tc.want.OVPNDomains) {
				t.Fatalf("ovpn domains = %v, want %v", cfg.OVPNDomains, tc.want.OVPNDomains)
			}
			if !slices.Equal(cfg.CorpDNS, tc.want.CorpDNS) {
				t.Fatalf("corp dns = %v, want %v", cfg.CorpDNS, tc.want.CorpDNS)
			}
		})
	}
}

func TestStepsHostAssembleCorpEnvAbortsOnInvalidExcludes(t *testing.T) {
	t.Setenv("CORP_EXCLUDE_SUBNETS", "10.0.0.0/8 not-a-cidr")
	t.Setenv("CORP_DOMAINS", "corp.example")
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())

	touched := false
	d := stepDeps{
		runLimactl: func(context.Context, ...string) (string, error) {
			touched = true
			return "", nil
		},
		vmIP: func() (string, error) {
			touched = true
			return "192.168.64.2", nil
		},
	}
	env, err := assembleCorpEnv(d)
	if err == nil || !strings.Contains(err.Error(), "not-a-cidr") {
		t.Fatalf("assemble = (%v, %v), want the invalid-CIDR error", env, err)
	}
	if touched {
		t.Fatal("assembly must abort before deriving subnets or the gateway")
	}
}

func TestStepsHostAssembleCorpEnv(t *testing.T) {
	t.Setenv("CORP_SUBNETS", "10.0.0.0/8 10.20.0.0/16") // bulk lists are dead: must be ignored
	t.Setenv("CORP_EXCLUDE_SUBNETS", "10.20.0.0/16")
	t.Setenv("CORP_DOMAINS", "corp.example")
	t.Setenv("CHECK_HOSTS", "wiki.corp.example gitlab.corp.example") // dead contract: must be ignored
	t.Setenv("BANK_PROBE_HOST", "wiki.corp.example")                 // the probe host contract now
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("CORP_DNS", "10.10.0.1") // else assembly goes DNS-hunting via limactl

	d := stepDeps{
		runLimactl: func(context.Context, ...string) (string, error) {
			t.Fatal("limactl must not run: no derivation is left in the assembly")
			return "", nil
		},
		vmIP: func() (string, error) { return "192.168.64.2", nil },
	}
	env, err := assembleCorpEnv(d)
	if err != nil {
		t.Fatalf("assemble = %v, want nil", err)
	}
	if !slices.Equal(env.Excluded, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}) {
		t.Fatalf("excluded = %v, want [10.20.0.0/16]", env.Excluded)
	}
	if env.Gateway != "192.168.64.2" || env.CheckHost != "wiki.corp.example" || env.CorpDomains == nil {
		t.Fatalf("corpEnv assembly incomplete: %+v", env)
	}
}

// The S6 probe host comes from the bank config contract (BANK_PROBE_HOST,
// default btg.wb-bank.ru): CHECK_HOSTS is dead and must not be read, while
// an empty CORP_DOMAINS stays an error.
func TestStepsHostAssembleCorpEnvProbeHostFromBankConfig(t *testing.T) {
	t.Setenv("CORP_EXCLUDE_SUBNETS", "")
	t.Setenv("CORP_DOMAINS", "corp.example")
	t.Setenv("CHECK_HOSTS", "wiki.corp.example") // dead contract: must be ignored
	t.Setenv("CORPVPN_STATE_DIR", t.TempDir())
	t.Setenv("CORP_DNS", "10.10.0.1")

	d := stepDeps{
		vmIP: func() (string, error) { return "192.168.64.2", nil },
	}
	env, err := assembleCorpEnv(d)
	if err != nil {
		t.Fatalf("assemble = %v, want nil", err)
	}
	if env.CheckHost != "btg.wb-bank.ru" {
		t.Fatalf("CheckHost = %q, want the bank-config default btg.wb-bank.ru", env.CheckHost)
	}

	t.Setenv("CORP_DOMAINS", "")
	if _, err := assembleCorpEnv(d); err == nil || !strings.Contains(err.Error(), "CORP_DOMAINS") {
		t.Fatalf("assemble without CORP_DOMAINS = %v, want an error naming CORP_DOMAINS only", err)
	}
}
