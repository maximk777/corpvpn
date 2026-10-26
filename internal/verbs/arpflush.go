// Package verbs implements the privileged host verbs a Sudoers grant may
// invoke (`corpvpn root-*`); each verb runs only fixed binaries with
// validated arguments. Package-injected `runner` is the exec seam for tests.
package verbs

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// runner is the package-injected exec seam: default shells out with
// exec.CommandContext; tests inject a fake.
type runner func(ctx context.Context, name string, args ...string) (string, error)

// realRunner is the production runner: combined output of the child process.
func realRunner(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// ClonedRoute is one gatewayless host route netstat reported.
type ClonedRoute struct {
	Addr  string // "10.15.0.82"
	Iface string // "bridge100"
}

// FindClonedRoutes parses `netstat -rn -f inet` output and returns host
// routes whose flags contain LLINFO and WASCLONED and that have no
// gateway, restricted to iface (empty = any).
func FindClonedRoutes(netstatOut, iface string) []ClonedRoute {
	var routes []ClonedRoute
	for _, line := range strings.Split(netstatOut, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		addr, err := netip.ParseAddr(f[0])
		if err != nil || !addr.Is4() {
			continue // header lines, "default", /32-suffixed interface routes
		}
		// Gatewayless: netstat prints the gateway column right after the
		// destination (link#N); accept it in the 3rd field as well since
		// column counts shift between netstat layouts.
		if !strings.HasPrefix(f[1], "link#") && !strings.HasPrefix(f[2], "link#") {
			continue
		}
		flags := -1
		for i, fld := range f {
			if strings.Contains(fld, "UHLWI") {
				flags = i
				break
			}
		}
		if flags < 0 {
			continue // not a host route (plain interface routes lack UHLWI)
		}
		if !strings.Contains(f[flags], "LLINFO") && f[len(f)-1] != "!" {
			continue // live resolved entry, not a stale clone
		}
		netif := ""
		if len(f) >= 4 {
			netif = f[3]
		}
		if iface != "" && netif != iface {
			continue
		}
		routes = append(routes, ClonedRoute{Addr: f[0], Iface: netif})
	}
	return routes
}

// FlushClonedRoutes deletes every route FindClonedRoutes reports for
// iface: `route -n delete -host <addr>` then `arp -d <addr>`, best
// effort per entry; returns the first error but deletes all.
func FlushClonedRoutes(iface string, run runner) error {
	out, err := run(context.Background(), "netstat", "-rn", "-f", "inet")
	if err != nil {
		return fmt.Errorf("arpflush: netstat: %w", err)
	}
	var firstErr error
	for _, r := range FindClonedRoutes(out, iface) {
		if _, err := run(context.Background(), "route", "-n", "delete", "-host", r.Addr); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("arpflush: route delete %s: %w", r.Addr, err)
		}
		if _, err := run(context.Background(), "arp", "-d", r.Addr); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("arpflush: arp delete %s: %w", r.Addr, err)
		}
	}
	return firstErr
}
