// steps_host.go adds S5 host network and S6 end-to-end probe to the
// reconcile procedure.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"corpvpn/internal/hostops"
	"corpvpn/internal/netutil"
	"corpvpn/internal/probe"
	"corpvpn/internal/reconcile"
	"golang.org/x/term"
)

const (
	stepHost  = "S5 host-net"
	stepProbe = "S6 end-to-end"

	// forwarderAddr is the scoped DNS forwarder: resolver files point at it
	// and S5 resolves its route targets through it.
	forwarderAddr = "127.0.0.1"
)

// corpEnv is the host-side network view assembled once per run from .env.
// The route set is not part of it anymore: S5 derives the bank addresses per
// run (forwarder cache, else BANK_PROBE_HOST through the forwarder), so the
// env only carries the invariants. Excluded stays behind for diagnostics and
// the per-address skip; the root process re-validates everything it receives.
type corpEnv struct {
	Excluded    []netip.Prefix // parsed CORP_EXCLUDE_SUBNETS
	Gateway     string         // Lima VM address on lima0 (vmIP)
	CorpDomains []string
	OVPNDomains []string
	CorpDNS     []string
	CheckHost   string // bank probe host (BANK_PROBE_HOST), probed by S6
	StateDir    string
}

// S5 route source and contested notification, package vars so tests inject
// fakes (same pattern as the internal/verbs seams).
var (
	bankAddrsFn       = defaultBankAddrs
	contestedNotifyFn = notify
)

// assembleCorpEnv builds corpEnv via the existing .env loader. Invalid
// CORP_EXCLUDE_SUBNETS entries abort before any mutation happens. Runs
// unprivileged: the gateway lookup goes through the injected limactl runner,
// which is why the root process must be handed ready-made values instead.
func assembleCorpEnv(d stepDeps) (*corpEnv, error) {
	if d.vmIP == nil {
		d.vmIP = vmIP
	}
	// The S6 probe host is the bank config contract (BANK_PROBE_HOST,
	// default btg.wb-bank.ru); CHECK_HOSTS is a dead contract, not read.
	bc, err := loadBankConfig(os.Getenv)
	if err != nil {
		return nil, err
	}
	env := &corpEnv{
		CorpDomains: strings.Fields(os.Getenv("CORP_DOMAINS")),
		OVPNDomains: strings.Fields(os.Getenv("OVPN_DOMAINS")),
		CorpDNS:     strings.Fields(os.Getenv("CORP_DNS")),
		CheckHost:   bc.BankProbeHost,
		StateDir:    stateDir(),
	}
	for _, s := range strings.Fields(os.Getenv("CORP_EXCLUDE_SUBNETS")) {
		p, err := netutil.ParseCIDRStrict(s)
		if err != nil {
			return nil, err
		}
		env.Excluded = append(env.Excluded, p)
	}
	gw, err := d.vmIP()
	if err != nil {
		return nil, err
	}
	env.Gateway = gw
	// CorpDNS fallback mirrors route-up.sh:82-88: .env -> gateway-pushed DNS
	// -> last-good cache. The forwarder's upstream is fed from here until the
	// daemon owns the wiring.
	if len(env.CorpDNS) == 0 {
		env.CorpDNS = corpDNSFromGuest(context.Background(), func(ctx context.Context, args ...string) (string, error) {
			return d.runLimactl(ctx, append([]string{"shell", vmName, "--"}, args...)...)
		})
		if len(env.CorpDNS) > 0 {
			fmt.Println("корп-DNS ловлю с шлюза:", strings.Join(env.CorpDNS, " "))
		}
	}
	if len(env.CorpDNS) == 0 {
		env.CorpDNS = corpDNSFromCache(env.StateDir)
		if len(env.CorpDNS) > 0 {
			fmt.Println("корп-DNS из кэша:", strings.Join(env.CorpDNS, " "))
		}
	}
	saveCorpDNSCache(env.StateDir, env.CorpDNS)
	// S6 cannot probe without a domain; the probe host always exists via the
	// bank config default, so only CORP_DOMAINS can make the probe
	// impossible. Fail before any mutation rather than silently shipping a
	// probe-less procedure.
	if len(env.CorpDomains) == 0 {
		return nil, fmt.Errorf("S6 probe needs CORP_DOMAINS in .env")
	}
	return env, nil
}

// defaultBankAddrs returns the addresses S5 must route: the forwarder's
// cached answers from the state dir when present, else BANK_PROBE_HOST
// resolved through the forwarder at 127.0.0.1 (pure Go resolver, so a wedged
// system resolver cannot interfere). Cache empty and forwarder unreachable is
// an error: silently installing nothing would leave S5 green without routes.
func defaultBankAddrs(ctx context.Context, env corpEnv) ([]netip.Addr, error) {
	if addrs := cachedBankAddrs(env.StateDir); len(addrs) > 0 {
		return addrs, nil
	}
	bc, err := loadBankConfig(os.Getenv)
	if err != nil {
		return nil, err
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, forwarderAddr+":53")
		},
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	names, err := r.LookupHost(cctx, bc.BankProbeHost)
	if err != nil {
		return nil, fmt.Errorf("forwarder %s: resolve %s: %w", forwarderAddr, bc.BankProbeHost, err)
	}
	var addrs []netip.Addr
	for _, n := range names {
		if a, aerr := netip.ParseAddr(n); aerr == nil && a.Is4() {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("forwarder %s: %s has no IPv4 answer", forwarderAddr, bc.BankProbeHost)
	}
	return addrs, nil
}

// cachedBankAddrs reads the forwarder's answer cache (hosts-cache.json in the
// state dir, written by the forwarder/daemon). Missing or unreadable cache
// means "no": the forwarder resolution takes over.
func cachedBankAddrs(stateDir string) []netip.Addr {
	b, err := os.ReadFile(filepath.Join(stateDir, "hosts-cache.json"))
	if err != nil {
		return nil
	}
	var entries []struct {
		Addr string `json:"addr"` // json matches "Addr" case-insensitively
	}
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil
	}
	var addrs []netip.Addr
	for _, e := range entries {
		if a, err := netip.ParseAddr(e.Addr); err == nil && a.Is4() {
			addrs = append(addrs, a)
		}
	}
	return addrs
}

// filterExcludedAddrs splits bank addresses into kept ones and the ones
// inside an excluded prefix. report, when non-nil, receives each skipped /32
// with the same "excluded by" message format the root path prints.
func filterExcludedAddrs(addrs []netip.Addr, excluded []netip.Prefix, report func(netip.Prefix)) (kept []netip.Addr) {
	for _, a := range addrs {
		p := netip.PrefixFrom(a, 32)
		if slices.ContainsFunc(excluded, func(e netip.Prefix) bool { return e.Contains(a) }) {
			if report != nil {
				report(p)
			}
			continue
		}
		kept = append(kept, a)
	}
	return kept
}

// corpDNSFromGuest reads the DNS the gateway pushes (vpnc-hook.sh parks it in
// /run/corpvpn/vpn-dns); empty output (file absent, guest down) means "no".
func corpDNSFromGuest(ctx context.Context, runLimactl func(context.Context, ...string) (string, error)) []string {
	out, err := runLimactl(ctx, "sh", "-c", `awk -F= '/^DNS=/{print $2}' /run/corpvpn/vpn-dns 2>/dev/null`)
	if err != nil {
		return nil
	}
	return strings.Fields(out)
}

func corpDNSFromCache(dir string) []string {
	b, err := os.ReadFile(filepath.Join(dir, "corp-dns"))
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

// saveCorpDNSCache keeps the last non-empty corp DNS for the next run, the
// same thing route-up.sh does with $STATE/corp-dns.
func saveCorpDNSCache(dir string, dns []string) {
	if len(dns) == 0 {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, "corp-dns"), []byte(strings.Join(dns, "\n")+"\n"), 0o644)
}

// hasNameserver reports whether a resolver file carries at least one
// nameserver line -- an empty file silently blackholes the whole domain.
func hasNameserver(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "nameserver ") {
			return true
		}
	}
	return false
}

// rootEnviron hands the validated values to the root process: under sudo
// neither limactl (instances are per-user) nor $HOME (/var/root) are usable,
// so root-net-up receives everything via the environment. The bank addresses
// ride in CORPVPN_SUBNETS as /32 prefixes. DNS_MODE is no longer overridden:
// an inherited value reaches root and is ignored there, the scoped resolver
// file being the only DNS behavior. Inherited values of the same keys are
// dropped so nothing stale leaks through.
func (e *corpEnv) rootEnviron(addrs []netip.Addr) []string {
	prefixes := make([]string, len(addrs))
	for i, a := range addrs {
		prefixes[i] = netip.PrefixFrom(a, 32).String()
	}
	overrides := [][2]string{
		{"CORPVPN_SUBNETS", strings.Join(prefixes, " ")},
		{"CORPVPN_GATEWAY", e.Gateway},
		{"CORPVPN_STATE_DIR", e.StateDir},
		{"CORP_DOMAINS", strings.Join(e.CorpDomains, " ")},
		{"OVPN_DOMAINS", strings.Join(e.OVPNDomains, " ")},
		{"CORP_DNS", strings.Join(e.CorpDNS, " ")},
	}
	out := make([]string, 0, len(os.Environ())+len(overrides))
	for _, kv := range os.Environ() {
		inherited := false
		for _, o := range overrides {
			if strings.HasPrefix(kv, o[0]+"=") {
				inherited = true
				break
			}
		}
		if !inherited {
			out = append(out, kv)
		}
	}
	for _, o := range overrides {
		out = append(out, o[0]+"="+o[1])
	}
	return out
}

// contestedEpisode dedups the once-per-episode contested notification; the
// entry clears when the address resolves via the VM gateway again.
var contestedEpisode sync.Map

func notifyContested(addr string) {
	if _, seen := contestedEpisode.LoadOrStore(addr, true); seen {
		return
	}
	contestedNotifyFn("corpvpn: " + addr + " занят другим VPN-клиентом, маршрут не трогаю")
}

func resetContested(addr string) { contestedEpisode.Delete(addr) }

// stepsHost returns S5 host-net and S6 end-to-end.
func stepsHost(d stepDeps, env *corpEnv) []reconcile.Step {
	// Production defaults so an unconfigured deps value still works; tests inject fakes.
	if d.runHost == nil {
		d.runHost = hostops.RealExec
	}
	if d.runSudo == nil {
		d.runSudo = sudoExec
	}
	if d.runRouteUp == nil {
		d.runRouteUp = sudoRouteUpScript
	}
	if d.check == nil {
		d.check = probe.New().Check
	}
	if d.stdinTTY == nil {
		d.stdinTTY = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	}
	if d.resolverDir == "" {
		d.resolverDir = "/etc/resolver"
	}
	return []reconcile.Step{
		{
			Name: stepHost,
			Ensure: func(ctx context.Context) error {
				addrs, err := bankAddrsFn(ctx, *env)
				if err != nil {
					return stepWrap(stepHost, err)
				}
				kept := filterExcludedAddrs(addrs, env.Excluded, func(p netip.Prefix) {
					fmt.Fprintf(os.Stderr, "excluded by CORP_EXCLUDE_SUBNETS: %s\n", p)
				})
				environ := env.rootEnviron(kept)
				// Fixed argv: exactly what the sudoers grant (install.sh)
				// allows. os.Executable returns the root-owned installed
				// path (/usr/local/bin/corpvpn), the same fixed path the
				// grant references -- no resolution needed.
				self, eerr := os.Executable()
				if eerr != nil {
					self = "corpvpn"
				}
				// Design trio: arp-flush runs BEFORE net-up -- a stale
				// cloned host route blackholes one IP even when the correct
				// /32 exists. Best-effort: a missed flush surfaces red via
				// S6's probe, it is not an S5 failure.
				if _, ferr := d.runSudo(ctx, []string{"-n", self, "root-arp-flush"}, environ); ferr != nil {
					fmt.Fprintf(os.Stderr, "root-arp-flush: %v (не критично, продолжаю)\n", ferr)
				}
				reached, err := d.runSudo(ctx, []string{"-n", self, "root-net-up"}, environ)
				if err == nil {
					// net-up pairs with the forwarder start (same env
					// passthrough); a forwarder that fails to start also
					// surfaces red via S6's probe.
					if _, ferr := d.runSudo(ctx, []string{"-n", self, "root-dns-fwd", "up"}, environ); ferr != nil {
						fmt.Fprintf(os.Stderr, "root-dns-fwd up: %v (не критично, S6 покажет)\n", ferr)
					}
					return nil
				}
				if reached {
					// corpvpn root-net-up ran and failed -- surface its error.
					return stepWrap(stepHost, err)
				}
				// sudo itself refused: the sudoers grant is absent. With a
				// terminal the pre-rework interactive script still works; from
				// the headless watchdog there is no way forward.
				if d.stdinTTY() {
					return stepWrap(stepHost, d.runRouteUp(ctx, environ))
				}
				return stepWrap(stepHost, errors.New("sudoers rule missing: run install.sh"))
			},
			Verify: func(ctx context.Context) error {
				return stepWrap(stepHost, verifyHostNet(ctx, d, env))
			},
		},
		{
			Name: stepProbe,
			// The probe has nothing to ensure: repairing S6 means re-running
			// S4 and S5, which the cascade from any earlier broken step
			// already does; a repair starting exactly here just re-probes.
			// Ensure must stay non-nil -- reconcile.RepairFrom calls it.
			Ensure: func(context.Context) error { return nil },
			Verify: func(ctx context.Context) error {
				return stepWrap(stepProbe, d.check(ctx, env.CorpDomains[0], env.CheckHost))
			},
		},
	}
}

// verifyHostNet checks S5's desired state per bank address: every address
// must resolve via the Lima gateway -- a missing route or a gatewayless
// clone fails and sends the reconcile back to Ensure; an address a foreign
// gateway owns is contested: notified once per episode, never fought, never
// an error. Every scoped resolver file must carry a nameserver line.
func verifyHostNet(ctx context.Context, d stepDeps, env *corpEnv) error {
	addrs, err := bankAddrsFn(ctx, *env)
	if err != nil {
		return err
	}
	for _, a := range filterExcludedAddrs(addrs, env.Excluded, nil) {
		out, err := d.runHost(ctx, "route", "-n", "get", a.String())
		if err != nil {
			return fmt.Errorf("route to %s: %w", a, err)
		}
		switch gw := routeGetGateway(out); gw {
		case env.Gateway:
			resetContested(a.String())
		case "":
			return fmt.Errorf("route to %s is a gatewayless clone, want gateway %s", a, env.Gateway)
		default:
			notifyContested(a.String())
			fmt.Println("занято чужим шлюзом", gw, "-- пропускаю:", a)
		}
	}
	for _, dom := range env.CorpDomains {
		b, err := os.ReadFile(filepath.Join(d.resolverDir, dom))
		if err != nil {
			return fmt.Errorf("resolver file missing: %w", err)
		}
		if !hasNameserver(b) {
			return fmt.Errorf("resolver file %s has no nameserver line -- DNS was applied empty", dom)
		}
	}
	return nil
}

// routeGetGateway extracts the gateway from `route -n get <net>` output (the
// "gateway: a.b.c.d" line).
func routeGetGateway(out string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "gateway:" {
			return f[1]
		}
	}
	return ""
}

// sudoExec is the production runSudo. reached reports whether the requested
// command actually started: sudo -n never prompts, so its own exit-1 messages
// mean the sudoers grant did not match and the command never ran.
func sudoExec(ctx context.Context, args []string, environ []string) (bool, error) {
	cmd := exec.CommandContext(ctx, "sudo", args...)
	cmd.Env = environ
	var stderr bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if sudoRefused(stderr.String()) {
		return false, err
	}
	return true, err
}

var sudoRefusalMarkers = []string{
	"a password is required",
	"not allowed to execute",
	"no tty present",
}

func sudoRefused(stderr string) bool {
	for _, m := range sudoRefusalMarkers {
		if strings.Contains(stderr, m) {
			return true
		}
	}
	return false
}

// sudoRouteUpScript is the interactive fallback: the pre-rework path with the
// validated values in the environment so route-up.sh derives nothing itself.
// sudo may prompt -- the caller checks for a TTY first.
func sudoRouteUpScript(ctx context.Context, environ []string) error {
	script := filepath.Join(repoRoot(), "host", "route-up.sh")
	cmd := exec.CommandContext(ctx, "sudo", script)
	cmd.Env = environ
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Dir = repoRoot()
	return cmd.Run()
}

// buildSteps returns the full S1-S6 reconcile procedure shared by up and heal.
func buildSteps(d stepDeps, env *corpEnv) []reconcile.Step {
	return append(stepsCore(d), stepsHost(d, env)...)
}
