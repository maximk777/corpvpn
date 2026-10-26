package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"corpvpn/internal/failure"
	"corpvpn/internal/reconcile"
)

// limaFake is an injectable runLimactl: it records every invocation (joined
// args) and answers from scripted fields. Anything not covered by a script
// returns ("", nil) -- the success shape of `ip link show` and
// `tmux has-session` when the probed thing exists.
type limaFake struct {
	calls       []string
	listOut     string
	listErr     error
	isActiveOut string
	isActiveErr error
	tun0Err     error
}

func (f *limaFake) run(_ context.Context, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	switch {
	case args[0] == "list":
		return f.listOut, f.listErr
	case slices.Contains(args, "is-active"):
		return f.isActiveOut, f.isActiveErr
	case f.tun0Err != nil && slices.Contains(args, vpnTun):
		return "", f.tun0Err
	default:
		return "", nil
	}
}

// dialFake is an injectable dial: it records dialled addresses and fails with
// err until repaired is flipped (models "ensure fixed the relay").
type dialFake struct {
	calls    []string
	conn     net.Conn
	err      error
	repaired bool
}

func (f *dialFake) dial(_ context.Context, addr string) (net.Conn, error) {
	f.calls = append(f.calls, addr)
	if f.err != nil && !f.repaired {
		return nil, f.err
	}
	return f.conn, nil
}

func pipeConn(t *testing.T) net.Conn {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() { _ = s.Close() })
	return c
}

type ensureCounters struct {
	connects int
	socks    int
}

// healthyDeps returns deps whose probes all succeed and whose mutating
// ensures only count invocations, so tests can assert they ran (or not).
func healthyDeps(lima *limaFake, dial *dialFake) (stepDeps, *ensureCounters) {
	cnt := &ensureCounters{}
	d := stepDeps{
		runLimactl:   lima.run,
		dial:         dial.dial,
		connect:      func(context.Context) error { cnt.connects++; return nil },
		installSocks: func() error { cnt.socks++; return nil },
	}
	return d, cnt
}

func healthyLima() *limaFake { return &limaFake{listOut: "vpnbox Running", isActiveOut: "active"} }

func TestStepsCoreHealthyPathVerifiesAllWithoutEnsures(t *testing.T) {
	lima := healthyLima()
	dial := &dialFake{conn: pipeConn(t)}
	d, cnt := healthyDeps(lima, dial)
	d.socksAddr = "127.0.0.1:9999"
	steps := stepsCore(d)

	broken, err := reconcile.VerifyAll(context.Background(), steps)
	if err != nil {
		t.Fatalf("VerifyAll returned error %v, want nil", err)
	}
	if broken != "" {
		t.Fatalf("VerifyAll broken = %q, want \"\"", broken)
	}
	if cnt.connects != 0 || cnt.socks != 0 {
		t.Fatalf("healthy path invoked ensures: %+v", cnt)
	}

	// Every verify reached its real probe; pin the exact limactl sequence.
	want := []string{
		"list",
		"shell " + vmName + " -- ip link show " + egressTun,
		"shell " + vmName + " -- systemctl is-active " + tun2socksUnit,
		"shell " + vmName + " -- sudo tmux has-session -t " + tmuxName,
		"shell " + vmName + " -- ip link show " + vpnTun,
	}
	if !slices.Equal(lima.calls, want) {
		t.Fatalf("limactl calls = %v, want %v", lima.calls, want)
	}
	if !slices.Equal(dial.calls, []string{"127.0.0.1:9999"}) {
		t.Fatalf("dial calls = %v, want [127.0.0.1:9999]", dial.calls)
	}
}

func TestStepsCoreRepairFromSocksWhenDialFails(t *testing.T) {
	lima := healthyLima()
	dial := &dialFake{conn: pipeConn(t), err: errors.New("connection refused")}
	d, cnt := healthyDeps(lima, dial)
	d.socksAddr = "127.0.0.1:9999"
	steps := stepsCore(d)

	broken, err := reconcile.VerifyAll(context.Background(), steps)
	if broken != "S3 socks" || err == nil {
		t.Fatalf("VerifyAll = (%q, %v), want (\"S3 socks\", error)", broken, err)
	}

	// S1 and S2 verified before the S3 dial failed.
	for _, want := range []string{
		"list",
		"shell " + vmName + " -- ip link show " + egressTun,
		"shell " + vmName + " -- systemctl is-active " + tun2socksUnit,
	} {
		if !slices.Contains(lima.calls, want) {
			t.Fatalf("expected verify probe %q missing from %v", want, lima.calls)
		}
	}

	// Repair starts at S3: its ensure runs (and fixes the relay), S1/S2
	// untouched, S4 re-ensured by the cascade as reconcile.RepairFrom defines.
	dial.repaired = true
	broken2, class, rerr := reconcile.RepairFrom(context.Background(), steps, broken)
	if rerr != nil {
		t.Fatalf("RepairFrom returned error %v, want nil", rerr)
	}
	if broken2 != "" || class != "" {
		t.Fatalf("RepairFrom = (%q, %q), want (\"\", \"\")", broken2, class)
	}
	if cnt.socks != 1 {
		t.Fatalf("S3 ensure invoked %d times, want 1", cnt.socks)
	}
	if cnt.connects != 1 {
		t.Fatalf("S4 ensure invoked %d times, want 1 (cascade re-ensures S4)", cnt.connects)
	}
}

func TestStepsCoreS4VerifyFailureClassifiesInfra(t *testing.T) {
	lima := &limaFake{
		listOut:     "vpnbox Running",
		isActiveOut: "active",
		tun0Err:     errors.New(`Interface "tun0" does not exist.`),
	}
	dial := &dialFake{conn: pipeConn(t)}
	d, cnt := healthyDeps(lima, dial)
	steps := stepsCore(d)

	broken, err := reconcile.VerifyAll(context.Background(), steps)
	if broken != "S4 tunnel" || err == nil {
		t.Fatalf("VerifyAll = (%q, %v), want (\"S4 tunnel\", error)", broken, err)
	}

	broken2, class, rerr := reconcile.RepairFrom(context.Background(), steps, broken)
	if broken2 != "S4 tunnel" || rerr == nil {
		t.Fatalf("RepairFrom = (%q, %v), want (\"S4 tunnel\", error)", broken2, rerr)
	}
	if class != failure.Infra {
		t.Fatalf("class = %q, want %q", class, failure.Infra)
	}
	if !strings.Contains(rerr.Error(), "S4 tunnel") {
		t.Fatalf("error %q not wrapped with step name", rerr)
	}
	if cnt.connects != 1 {
		t.Fatalf("S4 ensure invoked %d times, want 1", cnt.connects)
	}
}

func TestStepsCoreS4EnsureAuthErrorPassesThrough(t *testing.T) {
	lima := &limaFake{
		listOut:     "vpnbox Running",
		isActiveOut: "active",
		tun0Err:     errors.New("down"),
	}
	dial := &dialFake{conn: pipeConn(t)}
	d, _ := healthyDeps(lima, dial)
	d.connect = func(context.Context) error {
		return fmt.Errorf("%w: шлюз отверг учётные данные", failure.ErrAuth)
	}
	steps := stepsCore(d)

	_, class, err := reconcile.RepairFrom(context.Background(), steps, "S4 tunnel")
	if !errors.Is(err, failure.ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth preserved through step wrapping", err)
	}
	if class != failure.Auth {
		t.Fatalf("class = %q, want %q", class, failure.Auth)
	}
}

func TestStepsCoreS1VerifyFollowsLimactlList(t *testing.T) {
	cases := []struct {
		name    string
		listOut string
		listErr error
		wantErr bool
	}{
		{"running", "vpnbox Running", nil, false},
		{"stopped", "vpnbox Stopped", nil, true},
		{"missing from list", "NAME       STATUS\n", nil, true},
		{"limactl fails", "", errors.New("exit status 1"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lima := &limaFake{listOut: tc.listOut, listErr: tc.listErr}
			dial := &dialFake{conn: pipeConn(t)}
			d, _ := healthyDeps(lima, dial)
			steps := stepsCore(d)

			err := steps[0].Verify(context.Background())
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("verify = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("verify = nil, want error")
			}
			if !strings.Contains(err.Error(), "S1 vm-running") {
				t.Fatalf("error %q not wrapped with step name", err)
			}
		})
	}
}

func TestStepsCoreSocksDialDefaultsAndBudget(t *testing.T) {
	lima := healthyLima()
	dial := &dialFake{conn: pipeConn(t)}
	base := dial.dial
	d, _ := healthyDeps(lima, dial)
	var sawDeadline time.Duration
	d.dial = func(ctx context.Context, addr string) (net.Conn, error) {
		dl, ok := ctx.Deadline()
		if !ok {
			return nil, errors.New("S3 verify dial must carry a deadline")
		}
		sawDeadline = time.Until(dl)
		return base(ctx, addr)
	}
	steps := stepsCore(d) // socksAddr left empty: the documented default applies

	if err := steps[2].Verify(context.Background()); err != nil {
		t.Fatalf("verify = %v, want nil", err)
	}
	if !slices.Equal(dial.calls, []string{"192.168.64.1:1081"}) {
		t.Fatalf("dial = %v, want [192.168.64.1:1081]", dial.calls)
	}
	if sawDeadline > 5*time.Second {
		t.Fatalf("dial deadline %s exceeds the 5s budget", sawDeadline)
	}
}
