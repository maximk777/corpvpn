// Package netutil holds strict parsers and prefix math for host network ops.
package netutil

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// ParseCIDRStrict parses IPv4 CIDR "a.b.c.d/len"; rejects missing /len,
// non-IPv4, out-of-range octets and garbage.
func ParseCIDRStrict(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", s, err)
	}
	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: only IPv4 is accepted", s)
	}
	return p, nil
}

// ParseDomainStrict validates a DNS domain (labels a-z0-9-, total length <= 253).
func ParseDomainStrict(s string) error {
	if s == "" {
		return fmt.Errorf("empty domain")
	}
	if strings.HasSuffix(s, ".") {
		return fmt.Errorf("domain %q: trailing dot is not allowed", s)
	}
	if len(s) > 253 {
		return fmt.Errorf("domain %q: longer than 253 chars", s)
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return fmt.Errorf("domain %q: empty label", s)
		}
		if len(label) > 63 {
			return fmt.Errorf("domain %q: label %q is longer than 63 chars", s, label)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("domain %q: label %q has invalid char %q", s, label, r)
			}
		}
	}
	return nil
}

// ParseIfaceStrict validates an interface name (1-15 chars, [a-zA-Z0-9._-]).
// 15 chars = IFNAMSIZ-1 on Linux, the same cap route-up.sh consumers rely on.
func ParseIfaceStrict(s string) error {
	if s == "" {
		return fmt.Errorf("empty interface name")
	}
	if len(s) > 15 {
		return fmt.Errorf("interface name %q: longer than 15 chars", s)
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') &&
			r != '.' && r != '_' && r != '-' {
			return fmt.Errorf("interface name %q: invalid char %q", s, r)
		}
	}
	return nil
}

// Contains reports whether q lies inside p (both masked).
func Contains(p, q netip.Prefix) bool {
	p, q = p.Masked(), q.Masked()
	if p.Addr().Is4() != q.Addr().Is4() {
		return false
	}
	return q.Bits() >= p.Bits() && p.Contains(q.Addr())
}

// FilterExcluded splits subnets into kept and removed, where removed are
// all prefixes contained in any exclude prefix. Mirrors filter_excluded()
// from gitlab-exclusion task 1.1: a broader candidate is kept as-is,
// splitting excluded prefixes is out of scope.
func FilterExcluded(subnets, excludes []netip.Prefix) (kept, removed []netip.Prefix) {
	for _, s := range subnets {
		excluded := false
		for _, e := range excludes {
			if Contains(e, s) {
				excluded = true
				break
			}
		}
		if excluded {
			removed = append(removed, s)
		} else {
			kept = append(kept, s)
		}
	}
	return kept, removed
}

// route-up.sh never touches default and the /1 halves (they would send all
// Mac traffic into the VPN) nor the Lima link nets (they would cut the VM off).
var (
	dropDefault = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	limaLinkNets = []netip.Prefix{
		netip.MustParsePrefix("192.168.64.0/24"),
		netip.MustParsePrefix("192.168.5.0/24"),
	}
)

// DeriveGuestSubnets mirrors host/route-up.sh:41-56: it runs the guest
// command `ip -4 route show dev <tun>` for each tunnel (via runLimactl),
// parses destination prefixes, and drops default (0.0.0.0/0), the /1 halves
// (0.0.0.0/1, 128.0.0.0/1) and the Lima link nets 192.168.64.0/24, 192.168.5.0/24.
// runLimactl is injected for tests; production passes the limactl wrapper.
// Duplicates across tunnels are dropped (route-up.sh does `sort -u`); the
// result keeps first-seen order.
func DeriveGuestSubnets(ctx context.Context, runLimactl func(ctx context.Context, args ...string) (string, error), tunnels ...string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	seen := make(map[netip.Prefix]struct{})
	for _, tun := range tunnels {
		raw, err := runLimactl(ctx, "ip", "-4", "route", "show", "dev", tun)
		if err != nil {
			// An absent tun1 must not fail the derivation, same as the
			// `2>/dev/null; true` in route-up.sh; an empty set is the
			// caller's problem (it decides whether routes are installable).
			continue
		}
		for _, line := range strings.Split(raw, "\n") {
			fields := strings.Fields(line) // Fields also drops a trailing \r
			if len(fields) == 0 || fields[0] == "default" {
				continue
			}
			dst, err := ParseCIDRStrict(fields[0])
			if err != nil {
				return nil, fmt.Errorf("guest returned a non-CIDR destination %q (dev %s): %w", fields[0], tun, err)
			}
			if isOneOf(dst.Masked(), dropDefault) {
				continue
			}
			if isInsideAny(dst, limaLinkNets) {
				continue
			}
			if _, dup := seen[dst]; dup {
				continue
			}
			seen[dst] = struct{}{}
			out = append(out, dst)
		}
	}
	return out, nil
}

func isOneOf(p netip.Prefix, list []netip.Prefix) bool {
	for _, x := range list {
		if p == x {
			return true
		}
	}
	return false
}

func isInsideAny(p netip.Prefix, list []netip.Prefix) bool {
	for _, x := range list {
		if Contains(x, p) {
			return true
		}
	}
	return false
}
