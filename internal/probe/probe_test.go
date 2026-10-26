package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestCheckSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const corpDomain = "corp.internal"
	const checkHost = "check.internal"

	resolveCalls, dialCalls := 0, 0
	p := New()
	p.Resolve = func(ctx context.Context, host string) ([]string, error) {
		resolveCalls++
		if host != corpDomain {
			t.Errorf("Resolve host = %q, want %q", host, corpDomain)
		}
		return []string{"10.0.0.1"}, nil
	}
	p.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
		dialCalls++
		if want := net.JoinHostPort(checkHost, "443"); addr != want {
			t.Errorf("Dial addr = %q, want %q", addr, want)
		}
		return net.Dial(ln.Addr().Network(), ln.Addr().String())
	}

	if err := p.Check(context.Background(), corpDomain, checkHost); err != nil {
		t.Fatalf("Check() = %v, want nil", err)
	}
	if resolveCalls != 1 {
		t.Errorf("resolve calls = %d, want 1", resolveCalls)
	}
	if dialCalls != 1 {
		t.Errorf("dial calls = %d, want 1", dialCalls)
	}
}

func TestCheckResolveErrorPropagates(t *testing.T) {
	boom := errors.New("resolve failed")
	p := New()
	p.Resolve = func(ctx context.Context, host string) ([]string, error) {
		return nil, boom
	}
	p.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
		t.Error("Dial must not be called when resolve fails")
		return nil, nil
	}
	err := p.Check(context.Background(), "corp.internal", "check.internal")
	if !errors.Is(err, boom) {
		t.Fatalf("Check() = %v, want resolve error", err)
	}
}

func TestCheckDialErrorPropagates(t *testing.T) {
	boom := errors.New("dial failed")
	p := New()
	p.Resolve = func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.0.0.1"}, nil
	}
	p.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
		return nil, boom
	}
	err := p.Check(context.Background(), "corp.internal", "check.internal")
	if !errors.Is(err, boom) {
		t.Fatalf("Check() = %v, want dial error", err)
	}
}

func TestCheckDialTimeout(t *testing.T) {
	p := Prober{Timeout: 50 * time.Millisecond}
	p.Resolve = func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.0.0.1"}, nil
	}
	p.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	err := p.Check(context.Background(), "corp.internal", "check.internal")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Check() = %v, want context.DeadlineExceeded", err)
	}
}

func TestCheckRetriesUntilSuccess(t *testing.T) {
	dialCalls := 0
	p := New()
	p.Gap = time.Millisecond
	p.Resolve = func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.0.0.1"}, nil
	}
	p.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
		dialCalls++
		if dialCalls < 3 {
			return nil, fmt.Errorf("attempt %d: connection refused", dialCalls)
		}
		c, _ := net.Pipe()
		return c, nil
	}
	err := p.Check(context.Background(), "corp.internal", "check.internal")
	if err != nil {
		t.Fatalf("Check() = %v, want nil after retries", err)
	}
	if dialCalls != 3 {
		t.Errorf("dial calls = %d, want 3", dialCalls)
	}
}

func TestCheckRetriesExhaustedReturnsLastError(t *testing.T) {
	dialCalls := 0
	p := New()
	p.Gap = time.Millisecond
	p.Resolve = func(ctx context.Context, host string) ([]string, error) {
		return []string{"10.0.0.1"}, nil
	}
	p.Dial = func(ctx context.Context, addr string) (net.Conn, error) {
		dialCalls++
		return nil, fmt.Errorf("attempt %d failed", dialCalls)
	}
	err := p.Check(context.Background(), "corp.internal", "check.internal")
	const want = "attempt 3 failed"
	if err == nil || err.Error() != want {
		t.Fatalf("Check() = %v, want %q (the last attempt)", err, want)
	}
	if dialCalls != 3 {
		t.Errorf("dial calls = %d, want 3", dialCalls)
	}
}

func TestDefaultResolverIsPreferGoForwarder(t *testing.T) {
	// A local UDP listener stands in for the forwarder: the resolver's Dial
	// must connect there instead of the address the lookup asked about.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	forwarder := pc.LocalAddr().String()

	r := newForwarderResolver(forwarder)
	if !r.PreferGo {
		t.Fatal("default resolver must set PreferGo")
	}
	conn, err := r.Dial(context.Background(), "udp", "system.resolver.example:53")
	if err != nil {
		t.Fatalf("resolver Dial: %v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != forwarder {
		t.Errorf("resolver dialed %q, want forwarder %q", got, forwarder)
	}
}
