// Package hostops applies and removes Mac host routes and DNS.
// It runs as root via `sudo corpvpn root-net-up|root-net-down` (ADR-002);
// it executes only fixed binaries with validated arguments, never a shell.
package hostops

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"corpvpn/internal/netutil"
)

// execFunc runs a host binary and returns its combined output. Injected for
// tests; production passes RealExec.
type execFunc func(ctx context.Context, name string, args ...string) (stdout string, err error)

// RealExec is the production execFunc: exec.CommandContext with combined output.
func RealExec(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// hostBinaries is the complete set this package may ever execute: the sudoers
// grant covers only `corpvpn root-net-up|root-net-down`, so even a corrupted
// state file must not reach any other binary.
var hostBinaries = map[string]bool{"route": true, "networksetup": true}

func execHost(ctx context.Context, runExec execFunc, name string, args ...string) (string, error) {
	if !hostBinaries[name] {
		return "", fmt.Errorf("hostops: binary %q is not whitelisted", name)
	}
	return runExec(ctx, name, args...)
}

type Config struct {
	StateDir     string
	Subnets      []netip.Prefix // bank addresses as /32 host prefixes, exclusion-filtered
	CorpDomains  []string       // legacy passthrough list, validated only -- the resolver is NOT scoped per these domains
	OVPNDomains  []string       // same: validated only, never a resolver file
	CorpDNS      []string       // validated for the caller; resolver files point at the forwarder instead
	BankDomain   string         // the ONE scoped resolver domain (BANK_DOMAIN): the forwarder serves only bank names
	DNSMode      string         // legacy: still set by the root-net-up caller, ignored -- the scoped resolver file is the only DNS behavior
	IfaceGateway string         // Lima VM gateway address for `route -n add`
}

// NetReport is what ApplyNetReport surfaces to the S5 step: the bank
// addresses whose routes were held by a foreign gateway this pass. They are
// reclaimed (foreign route deleted, ours installed) but still reported so
// status shows the contention happened.
type NetReport struct {
	Contested []string
}

// resolverDir stands in for /etc/resolver; tests point it at a temp dir.
var resolverDir = "/etc/resolver"

// validate checks every configured value up front so ApplyNet can fail before
// touching routes, resolver files or system DNS.
func (c Config) validate() error {
	if c.StateDir == "" {
		return fmt.Errorf("hostops: empty StateDir")
	}
	for _, p := range c.Subnets {
		// Subnets arrive parsed; ParseCIDRStrict re-checks the IPv4-only rule.
		if _, err := netutil.ParseCIDRStrict(p.String()); err != nil {
			return fmt.Errorf("hostops: subnet: %w", err)
		}
	}
	for _, d := range c.CorpDomains {
		if err := netutil.ParseDomainStrict(d); err != nil {
			return fmt.Errorf("hostops: corp domain: %w", err)
		}
	}
	for _, d := range c.OVPNDomains {
		if err := netutil.ParseDomainStrict(d); err != nil {
			return fmt.Errorf("hostops: ovpn domain: %w", err)
		}
	}
	// The bank domain becomes a file name under resolverDir and lands in the
	// resolver state file RemoveNet re-parses strictly -- validate it here so
	// a malformed value dies before any mutation.
	if c.BankDomain != "" {
		if err := netutil.ParseDomainStrict(c.BankDomain); err != nil {
			return fmt.Errorf("hostops: bank domain: %w", err)
		}
	}
	gw, err := netip.ParseAddr(c.IfaceGateway)
	if err != nil {
		return fmt.Errorf("hostops: gateway %q: %w", c.IfaceGateway, err)
	}
	if !gw.Is4() {
		return fmt.Errorf("hostops: gateway %q: only IPv4 is accepted", c.IfaceGateway)
	}
	for _, ns := range c.CorpDNS {
		// Any valid IP; this also blocks newline injection into resolver files.
		if _, err := netip.ParseAddr(ns); err != nil {
			return fmt.Errorf("hostops: corp DNS %q: %w", ns, err)
		}
	}
	return nil
}

// ApplyNet keeps the plain-error signature for the root-net-up dispatch in
// main.go, which discards the report; steps_host.go uses ApplyNetReport.
func ApplyNet(ctx context.Context, cfg Config, runExec execFunc) error {
	_, err := ApplyNetReport(ctx, cfg, runExec)
	return err
}

// ApplyNetReport installs the bank /32 routes and the scoped resolver files,
// recording exactly what was applied into the same state files
// host/route-down.sh uses ($StateDir/routes, $StateDir/resolver) so the
// existing route-down.sh and RemoveNet stay consistent.
//
// The route loop works per bank address: `route -n get` decides before any
// mutation. A route already pointing at the VM gateway is left alone; a
// cloned gatewayless host route is deleted and re-added via the gateway; a
// `destination: default` fallback (macOS answers with the default-route
// entry when nothing specific exists) is not routed yet and gets the add; a
// specific route via a foreign gateway is fought (user-approved 2026-10-27:
// bank-derived addresses are re-claimed, the foreign path is the broken
// one) -- the foreign route is deleted and ours installed, with the address
// still reported as contested for visibility. Only actually-installed
// prefixes are recorded.
func ApplyNetReport(ctx context.Context, cfg Config, runExec execFunc) (NetReport, error) {
	if err := cfg.validate(); err != nil {
		return NetReport{}, err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		return NetReport{}, fmt.Errorf("hostops: state dir: %w", err)
	}

	var report NetReport
	var errs []error

	// Only prefixes whose route was installed by this pass (added, or healed
	// through a clone delete+re-add) are recorded, so RemoveNet never deletes
	// what S5 did not touch.
	routes, err := os.Create(filepath.Join(cfg.StateDir, "routes"))
	if err != nil {
		return NetReport{}, fmt.Errorf("hostops: routes state: %w", err)
	}
	defer routes.Close()
	for _, p := range cfg.Subnets {
		addr := p.Addr().String()
		out, gerr := execHost(ctx, runExec, "route", "-n", "get", addr)
		var gw, dest string
		if gerr == nil {
			gw = routeGatewayOf(out)
			dest = routeDestinationOf(out)
		}
		switch {
		case gerr == nil && gw == cfg.IfaceGateway:
			// Genuinely present and correct: nothing to install, nothing to record.
			continue
		case gerr == nil && gw == "":
			// A cloned ARP entry (apps ARPing while routes were down) shadows
			// the address with a gatewayless blackhole; heal it (incidents
			// 2026-10-23, 2026-10-26).
			if _, err := execHost(ctx, runExec, "route", append([]string{"-n", "delete"}, deleteArgs(p)...)...); err != nil {
				errs = append(errs, fmt.Errorf("route delete %s: %w", addr, err))
				continue
			}
		case gerr == nil && dest == "default":
			// macOS `route -n get` answers with the DEFAULT route entry when
			// no specific route exists (gateway = the LAN router): the
			// address is simply not routed yet, not owned by another VPN
			// client -- add it (live 2026-10-27: btg.wb-bank.ru was skipped
			// as contested here).
		case gerr == nil:
			// A specific route via a foreign gateway: another VPN client
			// (e.g. the user's OpenVPN) pushed its own /32 for the same
			// bank server, and the corp-DNS-derived address makes the
			// foreign path the broken one. User-approved deviation from
			// "never fight another world": delete the foreign route and
			// fall through to the add. The address stays in Contested so
			// status shows the contention happened.
			report.Contested = append(report.Contested, addr)
			if _, err := execHost(ctx, runExec, "route", append([]string{"-n", "delete"}, deleteArgs(p)...)...); err != nil {
				errs = append(errs, fmt.Errorf("route delete %s: %w", addr, err))
				continue
			}
		}
		if _, err := execHost(ctx, runExec, "route", "-n", "add", "-net", p.String(), cfg.IfaceGateway); err != nil {
			errs = append(errs, fmt.Errorf("route add %s: %w", p, err))
			continue
		}
		// Per-prefix verify: the installed route must resolve via the VM
		// gateway before the prefix is recorded.
		vout, verr := execHost(ctx, runExec, "route", "-n", "get", addr)
		if verr != nil || routeGatewayOf(vout) != cfg.IfaceGateway {
			errs = append(errs, fmt.Errorf("route to %s resolves via %q after add, want gateway %s", addr, routeGatewayOf(vout), cfg.IfaceGateway))
			continue
		}
		fmt.Fprintln(routes, p.String())
	}

	errs = append(errs, applyResolverDNS(cfg)...)
	return report, errors.Join(errs...)
}

// deleteArgs targets the clone deletion: a /32 is a host route (`-host`),
// anything else keeps the net form RemoveNet uses.
func deleteArgs(p netip.Prefix) []string {
	if p.IsSingleIP() {
		return []string{"-host", p.Addr().String()}
	}
	return []string{"-net", p.String()}
}

// routeGatewayOf extracts the "gateway: a.b.c.d" line from `route -n get`
// output; empty when the route has no gateway (cloned interface route).
func routeGatewayOf(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "gateway:" {
			return f[1]
		}
	}
	return ""
}

// routeDestinationOf extracts the "destination: ..." line from `route -n get`
// output. macOS answers "default" when no specific route exists -- the
// matched route is the default path, not one owning the queried address.
func routeDestinationOf(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "destination:" {
			return f[1]
		}
	}
	return ""
}

// applyResolverDNS writes exactly ONE /etc/resolver file: the bank domain,
// pointing at the local DNS forwarder on 127.0.0.1. The forwarder serves
// only names under the bank domain, so scoping any other domain here (a
// legacy CORP_DOMAINS entry like wb.ru) would black-hole its names -- the
// resolver admits the bank domain and nothing else. The domain is recorded
// into the resolver state file so RemoveNet removes exactly what was
// written.
func applyResolverDNS(cfg Config) []error {
	if cfg.BankDomain == "" {
		return nil
	}
	if err := os.MkdirAll(resolverDir, 0o755); err != nil {
		return []error{fmt.Errorf("hostops: %s: %w", resolverDir, err)}
	}
	const block = "nameserver 127.0.0.1\n"
	if err := os.WriteFile(filepath.Join(resolverDir, cfg.BankDomain), []byte(block), 0o644); err != nil {
		return []error{fmt.Errorf("resolver %s: %w", cfg.BankDomain, err)}
	}
	state, err := os.Create(filepath.Join(cfg.StateDir, "resolver"))
	if err != nil {
		return []error{fmt.Errorf("hostops: resolver state: %w", err)}
	}
	defer state.Close()
	fmt.Fprintln(state, cfg.BankDomain)
	return nil
}

// RemoveNet undoes everything recorded in the state files: deletes recorded
// routes, removes recorded /etc/resolver files, restores the saved DNS
// (networksetup -setdnsservers <svc> <orig...> or "Empty"). Mirrors
// host/route-down.sh:13-44.
func RemoveNet(ctx context.Context, stateDir string, runExec execFunc) error {
	var errs []error

	// routes (route-down.sh:18-23)
	routesPath := filepath.Join(stateDir, "routes")
	if b, err := os.ReadFile(routesPath); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			p, err := netutil.ParseCIDRStrict(line)
			if err != nil {
				// A tampered state file must not reach route(8).
				errs = append(errs, fmt.Errorf("routes state: %w", err))
				continue
			}
			out, err := execHost(ctx, runExec, "route", "-n", "delete", "-net", p.String())
			// Deleting an already-gone route is fine (route-down.sh ignores
			// it too); anything else is reported.
			if err != nil && !strings.Contains(strings.ToLower(out), "not in table") {
				errs = append(errs, fmt.Errorf("route delete %s: %w", p, err))
			}
		}
		removeFile(&errs, routesPath)
	}

	// resolver files (route-down.sh:25-30)
	resPath := filepath.Join(stateDir, "resolver")
	if b, err := os.ReadFile(resPath); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Recorded names become file paths under resolverDir; strict
			// domain validation blocks path traversal like "../../etc".
			if err := netutil.ParseDomainStrict(line); err != nil {
				errs = append(errs, fmt.Errorf("resolver state: %w", err))
				continue
			}
			if err := os.Remove(filepath.Join(resolverDir, line)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		removeFile(&errs, resPath)
	}

	// primary DNS restore (route-down.sh:33-44)
	primaryPath := filepath.Join(stateDir, "dns-primary")
	if b, err := os.ReadFile(primaryPath); err == nil {
		lines := strings.Split(string(b), "\n")
		svc := strings.TrimSpace(lines[0])
		var orig []string
		if len(lines) > 1 {
			orig = strings.Fields(lines[1])
		}
		if svc != "" {
			args := append([]string{"-setdnsservers", svc}, orig...)
			if len(orig) == 0 {
				args = append(args, "Empty") // no saved servers -> back to DHCP
			}
			if _, err := execHost(ctx, runExec, "networksetup", args...); err != nil {
				errs = append(errs, fmt.Errorf("networksetup -setdnsservers %s: %w", svc, err))
			}
		}
		removeFile(&errs, primaryPath)
	}

	return errors.Join(errs...)
}

func removeFile(errs *[]error, path string) {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		*errs = append(*errs, err)
	}
}
