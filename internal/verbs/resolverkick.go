package verbs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// scopedLookupTimeout bounds one dscacheutil probe: a wedged resolver
// usually answers nothing rather than slowly, so 6s is ample.
const scopedLookupTimeout = 6 * time.Second

// ResolverKick restarts the macOS system resolver: SIGTERM
// mDNSResponder (launchd respawns it). Escalates to `launchctl
// kickstart -k system/com.apple.mDNSResponder` when a plain killall is
// unavailable. Idempotent: a missing process is fine (launchd restarts).
func ResolverKick(run runner) error {
	out, err := run(context.Background(), "killall", "mDNSResponder")
	if err == nil {
		return nil
	}
	if errors.Is(err, exec.ErrNotFound) {
		if _, kerr := run(context.Background(), "launchctl", "kickstart", "-k", "system/com.apple.mDNSResponder"); kerr != nil {
			return fmt.Errorf("resolverkick: launchctl kickstart mDNSResponder: %w", kerr)
		}
		return nil
	}
	// killall exits 1 with this message when nothing matches; launchd
	// respawns mDNSResponder, so that state is success for us too.
	if strings.Contains(strings.ToLower(out), "no matching processes") {
		return nil
	}
	return fmt.Errorf("resolverkick: killall mDNSResponder: %w", err)
}

// ScopedLookupWorks answers whether the system resolver path can resolve
// the test name: runs `dscacheutil -q host -a name <name>` with a
// timeout and reports whether an ip_address/answer block came back.
func ScopedLookupWorks(ctx context.Context, run runner, testHost string) bool {
	ctx, cancel := context.WithTimeout(ctx, scopedLookupTimeout)
	defer cancel()
	out, err := run(ctx, "dscacheutil", "-q", "host", "-a", "name", testHost)
	if err != nil || strings.TrimSpace(out) == "" {
		return false
	}
	if strings.Contains(out, "ip_address") {
		return true
	}
	// Answer blocks always carry ip_address, but accept a bare
	// "name:" line followed by any line holding an address token.
	seenName := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "name:" {
			seenName = true
			continue
		}
		if !seenName {
			continue
		}
		for _, tok := range fields {
			if net.ParseIP(tok) != nil {
				return true
			}
		}
	}
	return false
}
