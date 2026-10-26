// Package authstate persists the consecutive auth-failure counter and the
// parked flag used by the auth circuit breaker (ADR-005).
//
// The watchdog invokes `corpvpn heal` as a fresh process every 30 s, so the
// counter lives in a JSON file in the corpvpn state dir and survives across
// processes. Writes go to a temp file in the same dir followed by a rename,
// which is atomic enough for the watchdog cadence.
package authstate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const MaxConsecutive = 2

const fileName = "auth-state.json"

type State struct {
	Consecutive int       `json:"consecutive"`
	Parked      bool      `json:"parked"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Load reads the state file; a missing file yields the zero state.
func Load(dir string) (State, error) {
	path := filepath.Join(dir, fileName)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("authstate: read %s: %w", path, err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, fmt.Errorf("authstate: parse %s: %w", path, err)
	}
	return st, nil
}

// RecordAuthFailure increments the counter, persists, and reports whether
// the breaker tripped (Consecutive >= MaxConsecutive).
func RecordAuthFailure(dir string) (parked bool, err error) {
	st, err := Load(dir)
	if err != nil {
		// Fail-safe: an unreadable counter must not uncap auth attempts
		// (a stale password must never burn the AD account).
		return true, err
	}
	st.Consecutive++
	st.Parked = st.Consecutive >= MaxConsecutive
	st.UpdatedAt = time.Now()
	return st.Parked, save(dir, st)
}

// RecordAuthSuccess resets the counter and parked flag after a healthy pass.
func RecordAuthSuccess(dir string) error {
	st, err := Load(dir)
	if err != nil {
		return err
	}
	if st.Consecutive == 0 && !st.Parked {
		return nil
	}
	return save(dir, State{UpdatedAt: time.Now()})
}

// Reset clears the state; called when credentials are updated or a manual up runs.
func Reset(dir string) error {
	path := filepath.Join(dir, fileName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("authstate: remove %s: %w", path, err)
	}
	return nil
}

// IsParked is a convenience loader for the heal short-circuit.
func IsParked(dir string) (bool, error) {
	st, err := Load(dir)
	if err != nil {
		return false, err
	}
	return st.Parked, nil
}

func save(dir string, st State) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("authstate: mkdir %s: %w", dir, err)
	}
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("authstate: encode: %w", err)
	}
	path := filepath.Join(dir, fileName)
	tmp, err := os.CreateTemp(dir, fileName+".tmp*")
	if err != nil {
		return fmt.Errorf("authstate: temp %s: %w", path, err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("authstate: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("authstate: close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("authstate: rename %s: %w", path, err)
	}
	return nil
}
