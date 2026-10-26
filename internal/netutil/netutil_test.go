package netutil

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func p(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestParseCIDRStrict(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    netip.Prefix
		wantErr bool
	}{
		{name: "valid cidr", in: "10.52.0.0/16", want: p("10.52.0.0/16")},
		{name: "missing len", in: "10.52.0.0", wantErr: true},
		{name: "non-numeric len", in: "10.0.0.0/x", wantErr: true},
		{name: "ipv6", in: "::/0", wantErr: true},
		{name: "octet out of range", in: "300.1.1.0/24", wantErr: true},
		{name: "len out of range", in: "10.0.0.0/33", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "empty addr", in: "/24", wantErr: true},
		{name: "negative len", in: "10.0.0.0/-1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseCIDRStrict(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseCIDRStrict(%q) = %v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCIDRStrict(%q) error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseCIDRStrict(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseDomainStrict(t *testing.T) {
	accept := []string{
		"wiki.corp.example",
		"gitlab",
		"a-b.c-d",
		// exactly 253 chars is the documented maximum
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." +
			strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
	}
	for _, in := range accept {
		if err := ParseDomainStrict(in); err != nil {
			t.Errorf("ParseDomainStrict(%q) error: %v, want nil", in, err)
		}
	}

	reject := []string{
		"",
		"gitlab_corp.example",    // '_' in label
		"gitlab.example.",        // trailing dot
		".gitlab.example",        // empty first label
		"gitlab..example",        // empty middle label
		"git lab.example",        // space
		"gitlab.example/x",       // path junk
		"Gitlab.example",         // charset is a-z0-9-
		strings.Repeat("a", 254), // total length > 253
		strings.Repeat("a", 64),  // label longer than 63
	}
	for _, in := range reject {
		if err := ParseDomainStrict(in); err == nil {
			t.Errorf("ParseDomainStrict(%q) = nil, want error", in)
		}
	}
}

func TestParseIfaceStrict(t *testing.T) {
	accept := []string{
		"tun0", "tun1", "lima0", "en0", "eth0.100", "br-lan", "a",
		"abcdefghijklmno", // 15 chars is the maximum
	}
	for _, in := range accept {
		if err := ParseIfaceStrict(in); err != nil {
			t.Errorf("ParseIfaceStrict(%q) error: %v, want nil", in, err)
		}
	}

	reject := []string{
		"",
		"abcdefghijklmnop", // 16 chars
		"tun0/x",
		"tun 0",
		"tun0:x",
	}
	for _, in := range reject {
		if err := ParseIfaceStrict(in); err == nil {
			t.Errorf("ParseIfaceStrict(%q) = nil, want error", in)
		}
	}
}

func TestContains(t *testing.T) {
	cases := []struct {
		name string
		p, q string
		want bool
	}{
		{name: "24 inside 16", p: "10.52.0.0/16", q: "10.52.3.0/24", want: true},
		{name: "sibling", p: "10.52.0.0/16", q: "10.53.0.0/24", want: false},
		{name: "equal", p: "10.52.0.0/16", q: "10.52.0.0/16", want: true},
		{name: "broader in narrower", p: "10.52.3.0/24", q: "10.52.0.0/16", want: false},
		// containment compares masked bits, so host bits set in the input are ignored
		{name: "unmasked inputs", p: "10.52.9.9/16", q: "10.52.3.7/24", want: true},
		{name: "default contains all v4", p: "0.0.0.0/0", q: "10.52.3.0/24", want: true},
		{name: "family mismatch", p: "0.0.0.0/0", q: "::/0", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Contains(p(tc.p), p(tc.q)); got != tc.want {
				t.Fatalf("Contains(%s, %s) = %v, want %v", tc.p, tc.q, got, tc.want)
			}
		})
	}
}

func TestFilterExcluded(t *testing.T) {
	cases := []struct {
		name        string
		subnets     []netip.Prefix
		excludes    []netip.Prefix
		wantKept    []netip.Prefix
		wantRemoved []netip.Prefix
	}{
		{
			// gitlab-exclusion 1.1: exact match excluded
			name:        "exact match removed",
			subnets:     []netip.Prefix{p("10.52.0.0/16")},
			excludes:    []netip.Prefix{p("10.52.0.0/16")},
			wantRemoved: []netip.Prefix{p("10.52.0.0/16")},
		},
		{
			name:        "contained candidate removed",
			subnets:     []netip.Prefix{p("10.52.3.0/24")},
			excludes:    []netip.Prefix{p("10.52.0.0/16")},
			wantRemoved: []netip.Prefix{p("10.52.3.0/24")},
		},
		{
			name:     "non-overlapping kept",
			subnets:  []netip.Prefix{p("10.53.0.0/24")},
			excludes: []netip.Prefix{p("10.52.0.0/16")},
			wantKept: []netip.Prefix{p("10.53.0.0/24")},
		},
		{
			// a broader candidate is kept; splitting prefixes is out of scope
			name:     "broader candidate kept",
			subnets:  []netip.Prefix{p("10.0.0.0/8")},
			excludes: []netip.Prefix{p("10.52.0.0/16")},
			wantKept: []netip.Prefix{p("10.0.0.0/8")},
		},
		{
			name:     "empty excludes keep everything",
			subnets:  []netip.Prefix{p("10.52.3.0/24"), p("10.53.0.0/24")},
			wantKept: []netip.Prefix{p("10.52.3.0/24"), p("10.53.0.0/24")},
		},
		{
			name:        "order preserved over mixed set",
			subnets:     []netip.Prefix{p("10.52.3.0/24"), p("10.53.0.0/24"), p("192.168.5.0/24")},
			excludes:    []netip.Prefix{p("10.52.0.0/16"), p("192.168.5.0/24")},
			wantKept:    []netip.Prefix{p("10.53.0.0/24")},
			wantRemoved: []netip.Prefix{p("10.52.3.0/24"), p("192.168.5.0/24")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, removed := FilterExcluded(tc.subnets, tc.excludes)
			if !slices.Equal(kept, tc.wantKept) {
				t.Fatalf("kept = %v, want %v", kept, tc.wantKept)
			}
			if !slices.Equal(removed, tc.wantRemoved) {
				t.Fatalf("removed = %v, want %v", removed, tc.wantRemoved)
			}
		})
	}
}

func TestDeriveGuestSubnets(t *testing.T) {
	routes := map[string]string{
		"tun0": strings.Join([]string{
			"default via 10.52.0.1 dev tun0",
			"10.52.3.0/24 dev tun0 scope link",
			"0.0.0.0/1 dev tun0",
			"128.0.0.0/1 dev tun0",
			// skip list applies to destinations regardless of the device in the line
			"192.168.64.0/24 dev lima0",
		}, "\n"),
		"tun1": strings.Join([]string{
			"10.53.0.0/24 dev tun1 metric 100",
			"10.52.3.0/24 dev tun1", // duplicate across tunnels: dropped by dedup
		}, "\n"),
	}
	var calls [][]string
	fake := func(ctx context.Context, args ...string) (string, error) {
		calls = append(calls, args)
		out, ok := routes[args[len(args)-1]]
		if !ok {
			return "", fmt.Errorf("Device %q does not exist", args[len(args)-1])
		}
		return out, nil
	}

	got, err := DeriveGuestSubnets(context.Background(), fake, "tun0", "tun1")
	if err != nil {
		t.Fatalf("DeriveGuestSubnets error: %v", err)
	}
	want := []netip.Prefix{p("10.52.3.0/24"), p("10.53.0.0/24")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DeriveGuestSubnets = %v, want %v", got, want)
	}
	if len(calls) != 2 {
		t.Fatalf("ran %d guest commands, want 2 (calls: %v)", len(calls), calls)
	}
	for i, tun := range []string{"tun0", "tun1"} {
		wantArgs := []string{"ip", "-4", "route", "show", "dev", tun}
		if !slices.Equal(calls[i], wantArgs) {
			t.Fatalf("guest command for %s: got %v, want %v", tun, calls[i], wantArgs)
		}
	}
}

func TestDeriveGuestSubnetsMissingTun1(t *testing.T) {
	// route-up.sh tolerates an absent tun1 (`2>/dev/null; true`)
	fake := func(ctx context.Context, args ...string) (string, error) {
		if args[len(args)-1] == "tun1" {
			return "", fmt.Errorf("Device \"tun1\" does not exist")
		}
		return "10.52.3.0/24 dev tun0\n", nil
	}
	got, err := DeriveGuestSubnets(context.Background(), fake, "tun0", "tun1")
	if err != nil {
		t.Fatalf("DeriveGuestSubnets error: %v", err)
	}
	if want := []netip.Prefix{p("10.52.3.0/24")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DeriveGuestSubnets = %v, want %v", got, want)
	}
}

func TestDeriveGuestSubnetsRejectsGarbage(t *testing.T) {
	fake := func(ctx context.Context, args ...string) (string, error) {
		return "10.52.3.99 dev tun0\n", nil // host route without /len is not a CIDR
	}
	if _, err := DeriveGuestSubnets(context.Background(), fake, "tun0"); err == nil {
		t.Fatalf("DeriveGuestSubnets = nil error, want error for non-CIDR destination")
	}
}
