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
	"golang.org/x/net/dns/dnsmessage"
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
	BankDomain  string // bank DNS scope (BANK_DOMAIN): S6's probe domain and the only /etc/resolver file
	StateDir    string
}

// S5 route source and contested notification, package vars so tests inject
// fakes (same pattern as the internal/verbs seams). limactlDefault is the
// assembly's fallback runner: healBuildSteps hands assembleCorpEnv a zero
// stepDeps{} and stepsCore's default lands only later, so the CORP_DNS
// guest hunt must resolve the seam itself.
var (
	bankAddrsFn       = defaultBankAddrs
	contestedNotifyFn = notify
	limactlDefault    = runLimactlExec
)

// forwarderEndpoint is the forwarder-liveness dial target: tests override
// it to an ephemeral fake DNS server, production keeps the forwarder.
var forwarderEndpoint = forwarderAddr + ":53"

// forwarderAlive performs a REAL DNS exchange with the forwarder, bypassing
// /etc/hosts: the Go resolver consults the hosts file BEFORE DNS, so a
// legacy hosts entry for the probe host makes LookupHost succeed even with
// a dead forwarder and the old resolver-based probe passed forever. Only
// the forwarder's own datagram counts: Success rcode with at least one
// answer; NXDOMAIN, refusal, timeout, truncation or garbage is "does not
// answer" and fails S5's verify, so the cascade restarts the process. The
// 3s bound lives on the socket deadline; ctx is checked around the
// exchange. The dns-fwd start is part of S5, so a dead forwarder must fail
// S5's verify -- the reconcile cascade then re-ensures S5 and its dns-fwd
// up restarts the process -- instead of surfacing only on S6, which has no
// Ensure of its own.
var forwarderAlive = func(ctx context.Context, env corpEnv) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// CheckHost is validated by loadBankConfig (lowercase labels, <=253
	// chars), so the FQDN form always fits a dnsmessage.Name.
	q := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(strings.TrimSuffix(env.CheckHost, ".") + "."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	buf, err := q.Pack()
	if err != nil {
		return fmt.Errorf("forwarder %s does not answer: %w", forwarderEndpoint, err)
	}
	conn, err := net.Dial("udp", forwarderEndpoint)
	if err != nil {
		return fmt.Errorf("forwarder %s does not answer: %w", forwarderEndpoint, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return fmt.Errorf("forwarder %s does not answer: %w", forwarderEndpoint, err)
	}
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("forwarder %s does not answer: %w", forwarderEndpoint, err)
	}
	// Fresh connected socket per query: the first datagram back belongs to
	// this query (the same trick internal/dnsfwd uses against upstream).
	rbuf := make([]byte, 1500)
	n, err := conn.Read(rbuf)
	if err != nil {
		return fmt.Errorf("forwarder %s does not answer: %w", forwarderEndpoint, err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("forwarder %s does not answer: %w", forwarderEndpoint, err)
	}
	var ans dnsmessage.Message
	if err := ans.Unpack(rbuf[:n]); err != nil {
		return fmt.Errorf("forwarder %s does not answer: %w", forwarderEndpoint, err)
	}
	if ans.Truncated {
		return fmt.Errorf("forwarder %s does not answer: %s: answer truncated", forwarderEndpoint, env.CheckHost)
	}
	if ans.RCode != dnsmessage.RCodeSuccess {
		return fmt.Errorf("forwarder %s does not answer: %s: rcode %s", forwarderEndpoint, env.CheckHost, ans.RCode)
	}
	if len(ans.Answers) == 0 {
		return fmt.Errorf("forwarder %s does not answer: %s: no answer records", forwarderEndpoint, env.CheckHost)
	}
	return nil
}

// assembleCorpEnv builds corpEnv via the existing .env loader. Invalid
// CORP_EXCLUDE_SUBNETS entries abort before any mutation happens. Runs
// unprivileged: the gateway lookup goes through the injected limactl runner,
// which is why the root process must be handed ready-made values instead.
func assembleCorpEnv(d stepDeps) (*corpEnv, error) {
	if d.vmIP == nil {
		d.vmIP = vmIP
	}
	// healBuildSteps passes a zero stepDeps{} and stepsCore applies the
	// production runner only later, so the CORP_DNS guest hunt below would
	// call a nil func without this fallback.
	if d.runLimactl == nil {
		d.runLimactl = limactlDefault
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
		BankDomain:  bc.BankDomain,
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
		env.CorpDNS = corpDNSFromGuest(context.Background(), guestDNSRunner(d.runLimactl))
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

// guestDNSRunner adapts a limactl runner for corpDNSFromGuest: the awk probe
// must run inside the guest ("shell", vmName, "--").
func guestDNSRunner(runLimactl func(context.Context, ...string) (string, error)) func(context.Context, ...string) (string, error) {
	return func(ctx context.Context, args ...string) (string, error) {
		return runLimactl(ctx, append([]string{"shell", vmName, "--"}, args...)...)
	}
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
	contestedNotifyFn("corpvpn: " + addr + " занят другим VPN-клиентом, возвращаю маршрут")
}

func resetContested(addr string) { contestedEpisode.Delete(addr) }

// stepsHost returns S5 host-net and S6 end-to-end.
func stepsHost(d stepDeps, env *corpEnv) []reconcile.Step {
	// Production defaults so an unconfigured deps value still works; tests inject fakes.
	if d.runHost == nil {
		d.runHost = hostops.RealExec
	}
	// buildSteps hands the same deps value to stepsCore and stepsHost, and
	// stepsCore's default lands on its own copy -- S5's guest DNS refresh
	// must resolve the seam itself, exactly like the assembly does.
	if d.runLimactl == nil {
		d.runLimactl = limactlDefault
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
				// Fresh upstream: S5 runs after S4 (tunnel up, vpnc-hook has
				// parked the gateway-pushed DNS in /run/corpvpn/vpn-dns),
				// while env.CorpDNS may be stale cache from an older session.
				// Refreshing here sends the working servers to root-net-up
				// and root-dns-fwd through the same environ and keeps the
				// cache file current.
				if fresh := corpDNSFromGuest(ctx, guestDNSRunner(d.runLimactl)); len(fresh) > 0 && !slices.Equal(fresh, env.CorpDNS) {
					env.CorpDNS = fresh
					saveCorpDNSCache(env.StateDir, fresh)
				}
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
				// The probe domain is the bank domain: legacy CORP_DOMAINS
				// entries are not served by the scoped forwarder and would
				// resolve to NXDOMAIN.
				return stepWrap(stepProbe, d.check(ctx, env.BankDomain, env.CheckHost))
			},
		},
	}
}

// verifyHostNet checks S5's desired state per bank address: every address
// must resolve via the Lima gateway -- a missing route or a gatewayless
// clone fails and sends the reconcile back to Ensure. A route held by a
// foreign gateway on a bank-derived address is a repair condition too
// (user-approved 2026-10-27): verify fails so the cascade re-ensures S5,
// which deletes the foreign route and installs ours. The scoped resolver
// file (the bank domain, the only one) must carry a nameserver line, and
// the forwarder must answer: a dead forwarder fails here so the cascade
// re-ensures S5 and restarts it.
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
		switch gw := routeGetGateway(out); {
		case gw == env.Gateway:
			resetContested(a.String())
		case gw == "":
			return fmt.Errorf("route to %s is a gatewayless clone, want gateway %s", a, env.Gateway)
		case routeGetDestination(out) == "default":
			// macOS `route -n get` answers with the DEFAULT route entry when
			// no specific route exists (gateway = the LAN router): the
			// address is missing, not contested -- fail so the cascade
			// re-ensures S5 and installs it.
			return fmt.Errorf("route to %s missing, want gateway %s", a, env.Gateway)
		default:
			// Foreign-held route on a bank-derived address: repair
			// condition (user-approved 2026-10-27), not a skip -- fail so
			// the cascade re-ensures S5, which reclaims the route. The
			// contested notification stays once per episode.
			notifyContested(a.String())
			return fmt.Errorf("route to %s held by foreign gateway %s, want %s", a, gw, env.Gateway)
		}
	}
	if env.BankDomain != "" {
		b, err := os.ReadFile(filepath.Join(d.resolverDir, env.BankDomain))
		if err != nil {
			return fmt.Errorf("resolver file %s missing: %w", env.BankDomain, err)
		}
		if !hasNameserver(b) {
			return fmt.Errorf("resolver file %s has no nameserver line -- DNS was applied empty", env.BankDomain)
		}
	}
	return forwarderAlive(ctx, *env)
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

// routeGetDestination extracts the matched destination from `route -n get`
// output. macOS answers "default" when no specific route exists -- the
// matched route is the default path, not one owning the queried address.
func routeGetDestination(out string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "destination:" {
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
