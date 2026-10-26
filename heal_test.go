// heal_test.go covers the watchdog heal pass: breaker short-circuit, log
// markers, auth parking on the second failure, and transition-gated
// notifications. Steps are injected, so no test touches the network.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"corpvpn/internal/authstate"
	"corpvpn/internal/failure"
	"corpvpn/internal/reconcile"
)

// healTestEnv points the state dir at a temp dir and silences notifications.
func healTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CORPVPN_STATE_DIR", dir)
	t.Setenv("NOTIFY", "0")
	return dir
}

// swapHealSteps replaces the step builder and restores it on cleanup; the
// returned flag records whether the builder ran at all.
func swapHealSteps(t *testing.T, build func(context.Context) ([]reconcile.Step, error)) *bool {
	t.Helper()
	called := false
	old := healBuildSteps
	healBuildSteps = func(ctx context.Context) ([]reconcile.Step, error) {
		called = true
		return build(ctx)
	}
	t.Cleanup(func() { healBuildSteps = old })
	return &called
}

// captureHealLog runs fn capturing everything written to stdout.
func captureHealLog(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	_ = w.Close()
	return <-done
}

func healthyFakeStep() []reconcile.Step {
	return []reconcile.Step{{
		Name:   stepTunnel,
		Ensure: func(context.Context) error { return nil },
		Verify: func(context.Context) error { return nil },
	}}
}

func TestHealParkedShortCircuitsWithoutSteps(t *testing.T) {
	dir := healTestEnv(t)
	if _, err := authstate.RecordAuthFailure(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := authstate.RecordAuthFailure(dir); err != nil {
		t.Fatal(err)
	}
	built := swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) {
		return []reconcile.Step{{Name: stepTunnel}}, nil
	})

	var runErr error
	log := captureHealLog(t, func() { runErr = runHeal(context.Background()) })

	if runErr != nil {
		t.Fatalf("runHeal = %v, want nil (parked pass exits 0)", runErr)
	}
	if *built {
		t.Fatal("parked pass must not build or invoke any step")
	}
	if !strings.Contains(log, "AUTH_PARKED") {
		t.Fatalf("log = %q, want the AUTH_PARKED marker", log)
	}
	if last := loadHealLast(dir); last.LastNotify != msgCredsRejected {
		t.Fatalf("notification = %q, want the credentials-rejected banner", last.LastNotify)
	}
}

func TestHealHealthyPassLogsOKAndRecordsAuthSuccess(t *testing.T) {
	dir := healTestEnv(t)
	if _, err := authstate.RecordAuthFailure(dir); err != nil { // arm the breaker
		t.Fatal(err)
	}
	swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) {
		return healthyFakeStep(), nil
	})

	var runErr error
	log := captureHealLog(t, func() { runErr = runHeal(context.Background()) })

	if runErr != nil {
		t.Fatalf("runHeal = %v, want nil", runErr)
	}
	if !strings.Contains(log, "HEAL_OK") {
		t.Fatalf("log = %q, want HEAL_OK", log)
	}
	if !strings.Contains(log, "STEP "+stepTunnel+" OK") {
		t.Fatalf("log = %q, want the step verdict", log)
	}
	st, err := authstate.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Consecutive != 0 || st.Parked {
		t.Fatalf("auth state = %+v, want reset by RecordAuthSuccess", st)
	}
	last := loadHealLast(dir)
	if !last.Healthy {
		t.Fatalf("heal-last = %+v, want healthy=true", last)
	}
	if last.LastNotify != msgRecovered {
		t.Fatalf("notification = %q, want the recovery banner on the false->true transition", last.LastNotify)
	}
}

func TestHealSteadyHealthyIsQuiet(t *testing.T) {
	dir := healTestEnv(t)
	if err := saveHealLast(dir, healLast{Healthy: true, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) {
		return healthyFakeStep(), nil
	})

	var runErr error
	_ = captureHealLog(t, func() { runErr = runHeal(context.Background()) })

	if runErr != nil {
		t.Fatalf("runHeal = %v, want nil", runErr)
	}
	if last := loadHealLast(dir); last.LastNotify != "" {
		t.Fatalf("notification = %q, want none while healthy stays true", last.LastNotify)
	}
}

func TestHealAuthFailureParksOnSecondPass(t *testing.T) {
	dir := healTestEnv(t)
	authErr := fmt.Errorf("%s: %w", stepTunnel, failure.ErrAuth)
	built := swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) {
		return []reconcile.Step{{
			Name:   stepTunnel,
			Ensure: func(context.Context) error { return authErr },
			Verify: func(context.Context) error { return errors.New("tmux session gone") },
		}}, nil
	})

	// Pass 1: first auth failure -- HEAL_AUTH_FAIL, exit 1, not parked yet.
	var firstErr error
	log1 := captureHealLog(t, func() { firstErr = runHeal(context.Background()) })
	if firstErr == nil {
		t.Fatal("pass 1 must exit non-zero on the auth failure")
	}
	if !strings.Contains(log1, "HEAL_AUTH_FAIL") {
		t.Fatalf("log = %q, want HEAL_AUTH_FAIL", log1)
	}
	if st, err := authstate.Load(dir); err != nil || st.Parked || st.Consecutive != 1 {
		t.Fatalf("state after pass 1 = (%+v, %v), want consecutive=1 unparked", st, err)
	}

	// Pass 2: second failure trips the breaker -- AUTH_BLOCKED, exit 0.
	var secondErr error
	log2 := captureHealLog(t, func() { secondErr = runHeal(context.Background()) })
	if secondErr != nil {
		t.Fatalf("parked pass must exit 0, got %v", secondErr)
	}
	if !strings.Contains(log2, "AUTH_BLOCKED") {
		t.Fatalf("log = %q, want AUTH_BLOCKED", log2)
	}
	st, err := authstate.Load(dir)
	if err != nil || !st.Parked {
		t.Fatalf("state after pass 2 = (%+v, %v), want parked", st, err)
	}
	if last := loadHealLast(dir); last.LastNotify != msgCredsRejected {
		t.Fatalf("notification = %q, want the credentials-rejected banner", last.LastNotify)
	}

	// Pass 3 stays parked: no step building, AUTH_PARKED in the log.
	*built = false
	var thirdErr error
	log3 := captureHealLog(t, func() { thirdErr = runHeal(context.Background()) })
	if thirdErr != nil {
		t.Fatalf("parked short-circuit = %v, want nil", thirdErr)
	}
	if *built {
		t.Fatal("parked short-circuit must not build steps")
	}
	if !strings.Contains(log3, "AUTH_PARKED") {
		t.Fatalf("log = %q, want AUTH_PARKED", log3)
	}
}

func TestHealInfraFailureLogsReasonAndNotifiesOnTransition(t *testing.T) {
	dir := healTestEnv(t)
	if err := saveHealLast(dir, healLast{Healthy: true, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) {
		return []reconcile.Step{{
			Name: stepVM,
			Ensure: func(context.Context) error {
				calls++
				return fmt.Errorf("limactl start: exit %d", calls)
			},
			Verify: func(context.Context) error { return errors.New("vm vpnbox is Stopped, want Running") },
		}}, nil
	})

	var runErr error
	log := captureHealLog(t, func() { runErr = runHeal(context.Background()) })

	if runErr == nil {
		t.Fatal("infra failure must exit non-zero")
	}
	if !strings.Contains(log, "HEAL_INFRA") || !strings.Contains(log, "limactl start: exit 1") {
		t.Fatalf("log = %q, want HEAL_INFRA with the failing step and reason", log)
	}
	if !strings.Contains(log, "STEP "+stepVM+" FAIL") {
		t.Fatalf("log = %q, want the failing step verdict", log)
	}
	last := loadHealLast(dir)
	if last.Healthy {
		t.Fatalf("heal-last = %+v, want healthy=false after the failed repair", last)
	}
	if !strings.Contains(last.LastNotify, stepVM) {
		t.Fatalf("notification = %q, want the failing step named", last.LastNotify)
	}

	// The second identical failure is no news: still exit 1, but the
	// notification must not repeat (only transitions notify).
	var runErr2 error
	captureHealLog(t, func() { runErr2 = runHeal(context.Background()) })
	if runErr2 == nil {
		t.Fatal("second infra failure must still exit non-zero")
	}
	last = loadHealLast(dir)
	if strings.Contains(last.LastNotify, "exit 2") {
		t.Fatalf("notification = %q, want no repeat while the outage continues", last.LastNotify)
	}
}

func TestHealRepairAfterBreakNotifiesRecovered(t *testing.T) {
	dir := healTestEnv(t)
	if err := saveHealLast(dir, healLast{Healthy: true, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	down := true
	swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) {
		return []reconcile.Step{{
			Name:   stepTunnel,
			Ensure: func(context.Context) error { down = false; return nil },
			Verify: func(context.Context) error {
				if down {
					return errors.New("tun0 up but blackholed")
				}
				return nil
			},
		}}, nil
	})

	var runErr error
	log := captureHealLog(t, func() { runErr = runHeal(context.Background()) })

	if runErr != nil {
		t.Fatalf("runHeal = %v, want nil after the successful repair", runErr)
	}
	if !strings.Contains(log, "STEP "+stepTunnel+" FAIL") || !strings.Contains(log, "HEAL_OK") {
		t.Fatalf("log = %q, want the FAIL verdict then HEAL_OK", log)
	}
	last := loadHealLast(dir)
	if !last.Healthy {
		t.Fatalf("heal-last = %+v, want healthy=true after the repair", last)
	}
	if last.LastNotify != msgRecovered {
		t.Fatalf("notification = %q, want the recovered banner after repairing a blackhole", last.LastNotify)
	}
}

func TestHealEnvErrorLogsMarkerAndExitsZero(t *testing.T) {
	healTestEnv(t)
	swapHealSteps(t, func(context.Context) ([]reconcile.Step, error) {
		return nil, errors.New("S6 probe needs CORP_DOMAINS and CHECK_HOSTS in .env")
	})

	var runErr error
	log := captureHealLog(t, func() { runErr = runHeal(context.Background()) })

	if runErr != nil {
		t.Fatalf("runHeal = %v, want nil (a config error is not retryable)", runErr)
	}
	if !strings.Contains(log, "HEAL_ENV_ERROR") {
		t.Fatalf("log = %q, want HEAL_ENV_ERROR", log)
	}
}

func TestHealShouldNotifyFiresOnlyOnStateChange(t *testing.T) {
	cases := []struct {
		prev, now, want bool
	}{
		{false, true, true},
		{true, false, true},
		{true, true, false},
		{false, false, false},
	}
	for _, tc := range cases {
		if got := shouldNotify(tc.prev, tc.now); got != tc.want {
			t.Errorf("shouldNotify(%v, %v) = %v, want %v", tc.prev, tc.now, got, tc.want)
		}
	}
}
