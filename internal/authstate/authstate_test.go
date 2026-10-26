package authstate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadMissingFileYieldsZeroState(t *testing.T) {
	dir := t.TempDir()
	st, err := Load(dir)
	if err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}
	if st.Consecutive != 0 || st.Parked || !st.UpdatedAt.IsZero() {
		t.Fatalf("expected zero state, got %+v", st)
	}
	if parked, err := IsParked(dir); err != nil || parked {
		t.Fatalf("IsParked on missing file = (%v, %v), want (false, nil)", parked, err)
	}
}

func TestRecordAuthFailureTripsOnSecondFailure(t *testing.T) {
	dir := t.TempDir()

	parked, err := RecordAuthFailure(dir)
	if err != nil {
		t.Fatalf("first RecordAuthFailure: %v", err)
	}
	if parked {
		t.Fatal("first failure must not park the breaker")
	}

	parked, err = RecordAuthFailure(dir)
	if err != nil {
		t.Fatalf("second RecordAuthFailure: %v", err)
	}
	if !parked {
		t.Fatal("second failure must trip the breaker")
	}

	st, err := Load(dir)
	if err != nil {
		t.Fatalf("Load after failures: %v", err)
	}
	if st.Consecutive != MaxConsecutive || !st.Parked {
		t.Fatalf("persisted state = %+v, want consecutive=%d parked=true", st, MaxConsecutive)
	}
	if st.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt must be set on failure")
	}
	if time.Since(st.UpdatedAt) > time.Minute {
		t.Fatalf("UpdatedAt not fresh: %v", st.UpdatedAt)
	}

	// Further failures keep it parked and do not reset the counter.
	parked, err = RecordAuthFailure(dir)
	if err != nil || !parked {
		t.Fatalf("third RecordAuthFailure = (%v, %v), want (true, nil)", parked, err)
	}
	if st, _ := Load(dir); st.Consecutive != MaxConsecutive+1 {
		t.Fatalf("counter kept incrementing past trip: %+v", st)
	}
}

func TestRecordAuthSuccessResets(t *testing.T) {
	dir := t.TempDir()
	if _, err := RecordAuthFailure(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordAuthFailure(dir); err != nil {
		t.Fatal(err)
	}

	if err := RecordAuthSuccess(dir); err != nil {
		t.Fatalf("RecordAuthSuccess: %v", err)
	}
	st, err := Load(dir)
	if err != nil {
		t.Fatalf("Load after success: %v", err)
	}
	if st.Consecutive != 0 || st.Parked {
		t.Fatalf("state after success = %+v, want zeroed", st)
	}
	if parked, err := IsParked(dir); err != nil || parked {
		t.Fatalf("IsParked after success = (%v, %v), want (false, nil)", parked, err)
	}
}

func TestResetClearsParkedState(t *testing.T) {
	dir := t.TempDir()
	if _, err := RecordAuthFailure(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordAuthFailure(dir); err != nil {
		t.Fatal(err)
	}
	if parked, err := IsParked(dir); err != nil || !parked {
		t.Fatalf("precondition: IsParked = (%v, %v), want (true, nil)", parked, err)
	}

	if err := Reset(dir); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	st, err := Load(dir)
	if err != nil {
		t.Fatalf("Load after Reset: %v", err)
	}
	if st.Consecutive != 0 || st.Parked || !st.UpdatedAt.IsZero() {
		t.Fatalf("state after Reset = %+v, want zero state", st)
	}
	if _, err := os.Stat(filepath.Join(dir, fileName)); !os.IsNotExist(err) {
		t.Fatalf("state file still present after Reset, stat err = %v", err)
	}
}

func TestCorruptedJSONReturnsClearError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load on corrupted JSON must return an error")
	}
	if !strings.Contains(err.Error(), fileName) {
		t.Fatalf("error must identify the state file, got: %v", err)
	}

	// IsParked returns not parked plus the error: fail-open is the caller's call.
	parked, err := IsParked(dir)
	if err == nil {
		t.Fatal("IsParked on corrupted JSON must return the error")
	}
	if parked {
		t.Fatal("IsParked on corrupted JSON must report not parked")
	}
}

func TestFailurePersistsAcrossLoads(t *testing.T) {
	// Stand-in for the fresh-process watchdog cadence: every call re-reads
	// the file, no in-memory state carries over.
	dir := t.TempDir()
	if _, err := RecordAuthFailure(dir); err != nil {
		t.Fatal(err)
	}
	parked, err := IsParked(dir)
	if err != nil || parked {
		t.Fatalf("IsParked after one failure = (%v, %v), want (false, nil)", parked, err)
	}
	if _, err := RecordAuthFailure(dir); err != nil {
		t.Fatal(err)
	}
	parked, err = IsParked(dir)
	if err != nil || !parked {
		t.Fatalf("IsParked after two failures = (%v, %v), want (true, nil)", parked, err)
	}
}

func TestWritesLeaveNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := RecordAuthFailure(dir); err != nil {
		t.Fatal(err)
	}
	if err := RecordAuthSuccess(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != fileName {
			t.Fatalf("leftover temp file %q in state dir", e.Name())
		}
	}
}
