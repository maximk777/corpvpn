// lima_test.go covers the egress freshness gate in ensureEgress: the guest
// resolv.conf must still hold the bootstrap DNS from egress-up.sh, otherwise
// egress is rebuilt. limactl is faked through the guestRunner seam, so no
// test touches the real VM.
package main

import (
	"errors"
	"strings"
	"testing"
)

const testSocks = "socks5://192.168.64.1:1081"

// freshResolv is what egress-up.sh writes into the guest.
const freshResolv = "nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions use-vc\n"

// stubGuest swaps guestRunner/guestPassthroughRunner for an in-memory VM:
// interfaces and the tun2socks unit look alive, resolv.conf holds resolv
// (resolvErr emulates a missing file). Returns the recorded passthrough
// command lines.
func stubGuest(t *testing.T, resolv string, resolvErr error) *[]string {
	t.Helper()
	passthrough := &[]string{}
	oldGuest, oldPass := guestRunner, guestPassthroughRunner
	guestRunner = func(args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(joined, "ip link show"):
			// tun0 отсутствует, чтобы stopCisco не ждал после pkill.
			if args[len(args)-1] == vpnTun {
				return "", errors.New("Device \"" + vpnTun + "\" does not exist")
			}
			return "state UP", nil
		case strings.HasPrefix(joined, "ip -4 route show default"):
			return "default via 10.0.0.1 dev " + egressTun, nil
		case strings.Contains(joined, "ExecStart"):
			return "/usr/local/bin/tun2socks --proxy " + testSocks, nil
		case strings.Contains(joined, "is-active"):
			return "active", nil
		case strings.HasPrefix(joined, "cat /etc/resolv.conf"):
			return resolv, resolvErr
		}
		return "", nil
	}
	guestPassthroughRunner = func(args ...string) error {
		*passthrough = append(*passthrough, strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { guestRunner, guestPassthroughRunner = oldGuest, oldPass })
	return passthrough
}

func egressUpCalled(calls []string) bool {
	for _, c := range calls {
		if strings.Contains(c, "egress-up.sh") {
			return true
		}
	}
	return false
}

func TestEnsureEgressFreshLeavesEgressAlone(t *testing.T) {
	passthrough := stubGuest(t, freshResolv, nil)

	if err := ensureEgress(testSocks, true); err != nil {
		t.Fatalf("ensureEgress = %v, want nil", err)
	}
	if len(*passthrough) != 0 {
		t.Fatalf("passthrough calls = %v, want none: fresh egress must not be rebuilt", *passthrough)
	}
}

func TestEnsureEgressPushedResolvConfTriggersRebuild(t *testing.T) {
	passthrough := stubGuest(t, "nameserver 10.15.12.100\nsearch wb-bank.ru", nil)

	if err := ensureEgress(testSocks, true); err != nil {
		t.Fatalf("ensureEgress = %v, want nil", err)
	}
	if !egressUpCalled(*passthrough) {
		t.Fatalf("passthrough calls = %v, want an egress-up.sh rebuild", *passthrough)
	}
}

func TestEnsureEgressMissingResolvConfTriggersRebuild(t *testing.T) {
	passthrough := stubGuest(t, "", errors.New("cat: /etc/resolv.conf: No such file or directory"))

	if err := ensureEgress(testSocks, true); err != nil {
		t.Fatalf("ensureEgress = %v, want nil", err)
	}
	if !egressUpCalled(*passthrough) {
		t.Fatalf("passthrough calls = %v, want an egress-up.sh rebuild", *passthrough)
	}
}

func TestResolvFreshIsWhitespaceTolerant(t *testing.T) {
	if !resolvFresh("nameserver  1.1.1.1\nnameserver\t8.8.8.8\noptions   use-vc\n") {
		t.Fatal("resolvFresh = false, want true for extra-whitespace bootstrap config")
	}
	if resolvFresh("# nameserver 1.1.1.1\noptions use-vc\n") {
		t.Fatal("resolvFresh = true, want false: nameserver inside a comment is not bootstrap DNS")
	}
}
