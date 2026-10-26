// steps.go assembles the reconcile steps from existing corpvpn machinery.
package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"corpvpn/internal/reconcile"
)

const (
	// Step names double as error prefixes, e.g. "S4 tunnel: ...".
	stepVM     = "S1 vm-running"
	stepEgress = "S2 egress"
	stepSocks  = "S3 socks"
	stepTunnel = "S4 tunnel"

	tun2socksUnit    = "corpvpn-tun2socks"
	defaultSocksAddr = "192.168.64.1:1081"
	socksDialTimeout = 5 * time.Second
)

type stepDeps struct {
	runLimactl   func(ctx context.Context, args ...string) (string, error) // reuse the lima.go wrapper in production
	dial         func(ctx context.Context, addr string) (net.Conn, error)
	connect      func(ctx context.Context) error // connectCisco in production
	installSocks func() error                    // installSocksAgent in production
	stateDir     string
	socksAddr    string // SOCKS_ADDR from .env, default 192.168.64.1:1081

	// S5/S6 seams; nil fields resolve to production defaults in stepsHost.
	runHost     func(ctx context.Context, name string, args ...string) (string, error) // hostops.RealExec
	runSudo     func(ctx context.Context, args []string, environ []string) (reached bool, err error)
	runRouteUp  func(ctx context.Context, environ []string) error             // sudo host/route-up.sh fallback
	check       func(ctx context.Context, corpDomain, checkHost string) error // probe.New().Check
	stdinTTY    func() bool
	resolverDir string                 // /etc/resolver stand-in for tests
	vmIP        func() (string, error) // gateway lookup for the corpEnv assembly
}

// stepsCore returns S1 VM running, S2 guest egress, S3 SOCKS relay,
// S4 Cisco tunnel.
func stepsCore(d stepDeps) []reconcile.Step {
	// Production defaults so an unconfigured deps value still works; tests inject fakes.
	if d.runLimactl == nil {
		d.runLimactl = runLimactlExec
	}
	if d.dial == nil {
		d.dial = dialTCP
	}
	if d.connect == nil {
		d.connect = func(context.Context) error { return connectCisco() }
	}
	if d.installSocks == nil {
		d.installSocks = installSocksAgent
	}
	if d.socksAddr == "" {
		d.socksAddr = defaultSocksAddr
	}

	return []reconcile.Step{
		{
			Name: stepVM,
			Ensure: func(context.Context) error {
				return stepWrap(stepVM, ensureVM())
			},
			Verify: func(ctx context.Context) error {
				out, err := d.runLimactl(ctx, "list")
				if err != nil {
					return stepWrap(stepVM, err)
				}
				for _, line := range strings.Split(out, "\n") {
					f := strings.Fields(line)
					if len(f) < 2 || f[0] != vmName {
						continue
					}
					if f[1] == "Running" {
						return nil
					}
					return stepWrap(stepVM, fmt.Errorf("vm %s is %s, want Running", vmName, f[1]))
				}
				return stepWrap(stepVM, fmt.Errorf("vm %s not found in limactl list", vmName))
			},
		},
		{
			Name: stepEgress,
			Ensure: func(context.Context) error {
				// Same PROXY_DNS default connectCisco uses.
				return stepWrap(stepEgress, ensureEgress(d.socksAddr, env("PROXY_DNS", "1") == "1"))
			},
			Verify: func(ctx context.Context) error {
				if _, err := d.runLimactl(ctx, "shell", vmName, "--", "ip", "link", "show", egressTun); err != nil {
					return stepWrap(stepEgress, err)
				}
				out, err := d.runLimactl(ctx, "shell", vmName, "--", "systemctl", "is-active", tun2socksUnit)
				if err != nil {
					return stepWrap(stepEgress, err)
				}
				if state := strings.TrimSpace(out); state != "active" {
					return stepWrap(stepEgress, fmt.Errorf("%s unit is %q, want active", tun2socksUnit, state))
				}
				return nil
			},
		},
		{
			Name: stepSocks,
			Ensure: func(context.Context) error {
				return stepWrap(stepSocks, d.installSocks())
			},
			Verify: func(ctx context.Context) error {
				ctx, cancel := context.WithTimeout(ctx, socksDialTimeout)
				defer cancel()
				conn, err := d.dial(ctx, d.socksAddr)
				if err != nil {
					return stepWrap(stepSocks, err)
				}
				if conn != nil {
					_ = conn.Close()
				}
				return nil
			},
		},
		{
			Name: stepTunnel,
			Ensure: func(ctx context.Context) error {
				// connectCisco wraps auth rejections with failure.ErrAuth;
				// %w keeps that classification intact for failure.Classify.
				return stepWrap(stepTunnel, d.connect(ctx))
			},
			Verify: func(ctx context.Context) error {
				if _, err := d.runLimactl(ctx, "shell", vmName, "--", "sudo", "tmux", "has-session", "-t", tmuxName); err != nil {
					return stepWrap(stepTunnel, err)
				}
				if _, err := d.runLimactl(ctx, "shell", vmName, "--", "ip", "link", "show", vpnTun); err != nil {
					return stepWrap(stepTunnel, err)
				}
				return nil
			},
		},
	}
}

// stepWrap prefixes a step error with the step name, preserving the cause.
func stepWrap(name string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", name, err)
}

// runLimactlExec is the production runLimactl: limactl with exactly these
// args on the host (guest probes pass "shell", vmName, "--", ...), stdout
// trimmed, stderr folded into the error like guest() in lima.go does.
func runLimactlExec(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "limactl", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("limactl %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

func dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", addr)
}
