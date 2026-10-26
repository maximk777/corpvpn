// Package probe implements the end-to-end VPN health check.
// A probe resolves a corp domain and dials a check host over the normal
// routing; it never sends credentials anywhere.
package probe

import (
	"context"
	"fmt"
	"net"
	"time"
)

const (
	defaultTimeout      = 5 * time.Second
	defaultResolverAddr = "127.0.0.1"
	defaultRetries      = 3
	defaultGap          = 2 * time.Second
)

type Prober struct {
	// Resolve resolves a hostname; defaults to a pure Go resolver that
	// queries the DNS forwarder at ResolverAddr.
	Resolve func(ctx context.Context, host string) ([]string, error)
	// Dial connects to "host:port"; defaults to a net.Dialer with Timeout.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// Timeout applies to each attempt, default 5s.
	Timeout time.Duration
	// ResolverAddr is the DNS forwarder host the default resolver queries;
	// default 127.0.0.1.
	ResolverAddr string
	// Retries is the number of Check attempts, default 3.
	Retries int
	// Gap is the pause between attempts, default 2s.
	Gap time.Duration
}

func New() Prober {
	return Prober{
		Timeout:      defaultTimeout,
		ResolverAddr: defaultResolverAddr,
		Retries:      defaultRetries,
		Gap:          defaultGap,
	}
}

// Check resolves corpDomain, then dials checkHost:443, closes the connection
// and returns nil on success. The whole resolve+dial sequence is retried
// Retries times with a Gap pause; the last error is returned only after the
// final attempt.
func (p Prober) Check(ctx context.Context, corpDomain, checkHost string) error {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	retries := p.Retries
	if retries <= 0 {
		retries = defaultRetries
	}
	gap := p.Gap
	if gap <= 0 {
		gap = defaultGap
	}
	if p.Resolve == nil {
		p.Resolve = newForwarderResolver(net.JoinHostPort(p.resolverAddr(), "53")).LookupHost
	}
	if p.Dial == nil {
		d := &net.Dialer{Timeout: timeout}
		p.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		}
	}

	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		if attempt > 1 {
			timer := time.NewTimer(gap)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		}
		err := p.attempt(ctx, corpDomain, checkHost, timeout)
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// attempt runs one resolve+dial sequence, each leg under its own timeout.
func (p Prober) attempt(ctx context.Context, corpDomain, checkHost string, timeout time.Duration) error {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	addrs, err := p.Resolve(rctx, corpDomain)
	cancel()
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return fmt.Errorf("probe: no addresses for %q", corpDomain)
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := p.Dial(dctx, net.JoinHostPort(checkHost, "443"))
	if err != nil {
		return err
	}
	return conn.Close()
}

func (p Prober) resolverAddr() string {
	if p.ResolverAddr != "" {
		return p.ResolverAddr
	}
	return defaultResolverAddr
}

// newForwarderResolver builds a pure Go resolver that sends every query to
// the forwarder address ("host:53"). PreferGo bypasses getaddrinfo, which
// can wedge under VPN-client DNS churn (2026-10-26); the Dial override
// replaces the /etc/resolv.conf servers. "udp" mirrors the stdlib docs
// example: the local forwarder answers A/AAAA in a single UDP exchange.
func newForwarderResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", addr)
		},
	}
}
