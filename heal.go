// heal.go — one watchdog pass of the reconcile procedure (ADR-001, ADR-005).
//
// Every return path logs a marker (HEAL_OK, HEAL_INFRA, HEAL_AUTH_FAIL,
// AUTH_PARKED, HEAL_ENV_ERROR): launchd redirects stdout to
// ~/Library/Logs/corpvpn-watchdog.log, so a marker line is the durable record
// of what the pass decided. Notifications fire only on health transitions;
// the recorded health and the last notification live in
// <stateDir>/heal-last.json and survive the per-tick process restart.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"corpvpn/internal/authstate"
	"corpvpn/internal/failure"
	"corpvpn/internal/reconcile"
)

const healLastFile = "heal-last.json"

const (
	msgCredsRejected = "corpvpn: VPN credentials rejected — run corpvpn creds"
	msgRecovered     = "corpvpn: VPN recovered after sleep or outage"
)

// healBuildSteps assembles the production S1-S6 procedure (tasks 2.7, 2.8).
// A variable so tests inject a step builder without touching the network.
var healBuildSteps = func(ctx context.Context) ([]reconcile.Step, error) {
	d := stepDeps{}
	cenv, err := assembleCorpEnv(d)
	if err != nil {
		return nil, err
	}
	return buildSteps(d, cenv), nil
}

// cmdHeal is the launchd entry point: one reconcile pass. Exit 0 when the
// outcome needs no retry (healthy, parked, invalid config), 1 otherwise.
func cmdHeal() error { return runHeal(context.Background()) }

func runHeal(ctx context.Context) error {
	dir := stateDir()

	// 1. Auth breaker: parked credentials must never rebuild the tunnel —
	// a stale password would keep burning login attempts.
	if parked, _ := authstate.IsParked(dir); parked {
		logLine("AUTH_PARKED credentials rejected earlier; run corpvpn creds, then corpvpn up")
		notifyOnce(msgCredsRejected)
		return nil
	}

	// 2. Env + steps (tasks 2.7, 2.8); invalid config aborts before any mutation.
	steps, err := healBuildSteps(ctx)
	if err != nil {
		logLine("HEAL_ENV_ERROR %v", err)
		return nil
	}
	prevHealthy := loadHealLast(dir).Healthy

	// 3. Verify every step and log each verdict before repairing, so a
	// broken pass records the whole picture even where repair never reaches.
	// firstBroken matches reconcile.VerifyAll's semantics.
	firstBroken := ""
	for _, s := range steps {
		if verr := s.Verify(ctx); verr != nil {
			logLine("STEP %s FAIL class=%s: %v", s.Name, failure.Classify(verr), verr)
			if firstBroken == "" {
				firstBroken = s.Name
			}
			continue
		}
		logLine("STEP %s OK", s.Name)
	}

	if firstBroken == "" {
		if err := authstate.RecordAuthSuccess(dir); err != nil {
			logLine("HEAL_OK (auth state reset failed: %v)", err)
		} else {
			logLine("HEAL_OK")
		}
		healRecordHealthy(dir, true)
		if shouldNotify(prevHealthy, true) {
			notifyMarked(msgRecovered)
		}
		return nil
	}

	// The detected breakage is the outage: record it before repairing so a
	// same-pass recovery counts as a false->true transition.
	healRecordHealthy(dir, false)

	// 4. Repair from the first broken step; the cascade re-ensures the rest.
	broken, class, rerr := reconcile.RepairFrom(ctx, steps, firstBroken)
	if rerr == nil {
		_ = authstate.RecordAuthSuccess(dir)
		healRecordHealthy(dir, true)
		logLine("HEAL_OK")
		// A transition is guaranteed: healthy was recorded false above.
		notifyMarked(msgRecovered)
		return nil
	}

	// 5. Repair failed: classify, park after MaxConsecutive auth failures.
	if class == failure.Auth {
		parked, ferr := authstate.RecordAuthFailure(dir)
		if ferr != nil {
			// Fail-safe: an unreadable counter must not uncap auth attempts.
			logLine("AUTH_BLOCKED auth state unreadable, parking: %v", ferr)
			notifyOnce(msgCredsRejected)
			return nil
		}
		if parked {
			logLine("AUTH_BLOCKED credentials rejected %d times; run corpvpn creds, then corpvpn up", authstate.MaxConsecutive)
			notifyOnce(msgCredsRejected)
			return nil
		}
		logLine("HEAL_AUTH_FAIL %v", rerr)
		return rerr
	}
	logLine("HEAL_INFRA %v", rerr)
	if shouldNotify(prevHealthy, false) {
		notifyMarked(fmt.Sprintf("corpvpn: VPN recovery failed — %s: %v", broken, rerr))
	}
	return rerr
}

// healLast is the bookkeeping between watchdog passes: the health recorded by
// the previous pass (transition gating) and the last notification sent (so a
// persisting condition does not re-notify every 30 s).
type healLast struct {
	Healthy    bool      `json:"healthy"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastNotify string    `json:"last_notify,omitempty"`
}

// loadHealLast treats a missing or unreadable file as "no previous state":
// the worst case is one extra notification, never a missed recovery.
func loadHealLast(dir string) healLast {
	b, err := os.ReadFile(filepath.Join(dir, healLastFile))
	if err != nil {
		return healLast{}
	}
	var st healLast
	if json.Unmarshal(b, &st) != nil {
		return healLast{}
	}
	return st
}

func saveHealLast(dir string, st healLast) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("heal: mkdir %s: %w", dir, err)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("heal: encode: %w", err)
	}
	path := filepath.Join(dir, healLastFile)
	tmp, err := os.CreateTemp(dir, healLastFile+".tmp*")
	if err != nil {
		return fmt.Errorf("heal: temp %s: %w", path, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("heal: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("heal: close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("heal: rename %s: %w", path, err)
	}
	return nil
}

// healRecordHealthy persists the health for the next pass's transition check.
// A persistence failure only degrades notification dedup, so it is not fatal.
func healRecordHealthy(dir string, healthy bool) {
	st := loadHealLast(dir)
	st.Healthy = healthy
	st.UpdatedAt = time.Now()
	_ = saveHealLast(dir, st)
}

// shouldNotify reports a health transition: notifications fire only when the
// recorded health differs from the current one.
func shouldNotify(prev, now bool) bool { return prev != now }

// notifyOnce sends msg unless it is already the last notification, so the
// parked banner stays quiet while nothing changes between ticks.
func notifyOnce(msg string) {
	if loadHealLast(stateDir()).LastNotify == msg {
		return
	}
	notifyMarked(msg)
}

// notifyMarked sends msg and records it as the last notification.
func notifyMarked(msg string) {
	notify(msg)
	st := loadHealLast(stateDir())
	st.LastNotify = msg
	st.UpdatedAt = time.Now()
	_ = saveHealLast(stateDir(), st)
}

// logLine writes one heal line to stdout; launchd redirects it to
// ~/Library/Logs/corpvpn-watchdog.log.
func logLine(format string, args ...any) {
	fmt.Printf("[heal] "+format+"\n", args...)
}
