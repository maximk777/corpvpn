package verbs

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"corpvpn/internal/dnsfwd"
)

// routeInstaller implements dnsfwd.RouteInstaller by shelling out to
// /sbin/route. gw is the guest gateway every installed /32 points at;
// Add uses it instead of its interface parameter because the production
// wiring always constructs the installer with the same gateway the
// OnAnswer sink answers with (the parameter exists for test fakes).
type routeInstaller struct {
	gw [4]byte
}

var _ dnsfwd.RouteInstaller = (*routeInstaller)(nil)

// newRouteInstaller takes the guest gateway (the Lima VM address on
// lima0, e.g. 192.168.64.1) as the target of every dynamic /32.
func newRouteInstaller(guestGW [4]byte) *routeInstaller {
	return &routeInstaller{gw: guestGW}
}

func (ri *routeInstaller) Add(addr, _ [4]byte) (bool, error) {
	if _, err := runRoute("-n", "add", "-net", quad(addr)+"/32", quad(ri.gw)); err != nil {
		return false, fmt.Errorf("route add %s: %w", quad(addr), err)
	}
	return true, nil
}

func (ri *routeInstaller) RouteOf(addr [4]byte) (string, string, error) {
	out, err := runRoute("-n", "get", quad(addr))
	if err != nil {
		return "", "", fmt.Errorf("route get %s: %w", quad(addr), err)
	}
	return routeGatewayOf(out), routeDestinationOf(out), nil
}

func (ri *routeInstaller) Remove(addr [4]byte) error {
	out, err := runRoute("-n", "delete", quad(addr))
	if err != nil {
		// Keep route(8)'s own words ("not in table") in the error so
		// callers can classify no-match deletes.
		return fmt.Errorf("route delete %s: %s: %w", quad(addr), strings.TrimSpace(out), err)
	}
	return nil
}

// runRoute shells out to /sbin/route; CombinedOutput carries the human
// output to the caller.
func runRoute(args ...string) (string, error) {
	out, err := exec.Command("/sbin/route", args...).CombinedOutput()
	return string(out), err
}

// quad renders a dotted quad, the form route(8) speaks.
func quad(a [4]byte) string {
	return netip.AddrFrom4(a).String()
}

// routeGatewayOf/routeDestinationOf are small local copies of the
// hostops parsers of the same names: verbs must not depend on hostops
// internals, and the `route -n get` output format is stable.

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

// routeDestinationOf extracts the "destination: ..." line from
// `route -n get` output. macOS answers "default" when no specific route
// exists -- the matched route is the default path, not one owning the
// queried address.
func routeDestinationOf(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "destination:" {
			return f[1]
		}
	}
	return ""
}
