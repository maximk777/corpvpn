package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// runCycles drives Run and lets `loops` iterations through before the
// fake sleep cancels the context; it returns the recorded sleep pauses.
func runCycles(t *testing.T, d *Daemon, loops int) []time.Duration {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var slept []time.Duration
	d.Sleep = func(_ context.Context, dur time.Duration) {
		slept = append(slept, dur)
		if len(slept) >= loops {
			cancel()
		}
	}
	if err := d.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v, want context.Canceled", err)
	}
	return slept
}

func writeDesiredForTest(t *testing.T, path string, d Desired) {
	t.Helper()
	if err := WriteDesired(path, d); err != nil {
		t.Fatal(err)
	}
}

func TestRunDownNeverProbesOrRepairs(t *testing.T) {
	dir := t.TempDir()
	desired := filepath.Join(dir, "desired.json")
	writeDesiredForTest(t, desired, Down)
	probeCalls, reconcileCalls := 0, 0
	d := &Daemon{
		DesiredPath: desired,
		StatusPath:  filepath.Join(dir, "status.json"),
		Probe: func(context.Context) error {
			probeCalls++
			return nil
		},
		Reconcile: func(context.Context, func(string, error)) error {
			reconcileCalls++
			return nil
		},
		EachTick: func(context.Context) {
			t.Error("EachTick must not run while desired=down")
		},
	}
	slept := runCycles(t, d, 1)
	if probeCalls != 0 || reconcileCalls != 0 {
		t.Fatalf("desired=down must not probe or repair: probes=%d reconciles=%d", probeCalls, reconcileCalls)
	}
	if len(slept) != 1 || slept[0] != 10*time.Second {
		t.Fatalf("sleep = %v, want the default 10s interval once", slept)
	}
	st, err := ReadStatus(d.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Desired != Down || st.Probe != "" || st.Steps != nil {
		t.Fatalf("down status = %+v, want desired=down probe=\"\" steps=nil", st)
	}
	if st.UpdatedAt.IsZero() {
		t.Fatal("updated_at not set")
	}
}

func TestRunUpProbeOKWritesGreenStatus(t *testing.T) {
	dir := t.TempDir()
	desired := filepath.Join(dir, "desired.json")
	writeDesiredForTest(t, desired, Up)
	probeCalls := 0
	d := &Daemon{
		DesiredPath: desired,
		StatusPath:  filepath.Join(dir, "status.json"),
		Interval:    3 * time.Second,
		Probe: func(context.Context) error {
			probeCalls++
			return nil
		},
		Reconcile: func(context.Context, func(string, error)) error {
			t.Error("reconcile must not run on a green probe")
			return nil
		},
	}
	slept := runCycles(t, d, 1)
	if probeCalls != 1 {
		t.Fatalf("probes = %d, want 1", probeCalls)
	}
	if len(slept) != 1 || slept[0] != 3*time.Second {
		t.Fatalf("sleep = %v, want Interval once", slept)
	}
	st, err := ReadStatus(d.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Desired != Up || st.Probe != "ok" || st.Steps != nil {
		t.Fatalf("green status = %+v, want desired=up probe=ok steps=nil", st)
	}
}

func TestRunRedProbeReconcilesOnceReprobesGreen(t *testing.T) {
	dir := t.TempDir()
	desired := filepath.Join(dir, "desired.json")
	writeDesiredForTest(t, desired, Up)
	probeCalls, reconcileCalls := 0, 0
	boom := errors.New("S3 dns forwarder died")
	d := &Daemon{
		DesiredPath: desired,
		StatusPath:  filepath.Join(dir, "status.json"),
		Probe: func(context.Context) error {
			probeCalls++
			if probeCalls == 1 {
				return errors.New("probe: red")
			}
			return nil // re-probe after the reconcile pass is green
		},
		Reconcile: func(_ context.Context, report func(string, error)) error {
			reconcileCalls++
			report("S1", nil)
			report("S3", boom)
			return boom
		},
	}
	slept := runCycles(t, d, 1)
	if reconcileCalls != 1 {
		t.Fatalf("reconciles = %d, want 1", reconcileCalls)
	}
	if probeCalls != 2 {
		t.Fatalf("probes = %d, want initial + re-probe = 2", probeCalls)
	}
	if len(slept) != 1 || slept[0] != 10*time.Second {
		t.Fatalf("sleep = %v, want the default Interval after a green re-probe", slept)
	}
	st, err := ReadStatus(d.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	wantSteps := map[string]string{"S1": "ok", "S3": boom.Error()}
	if !reflect.DeepEqual(st.Steps, wantSteps) {
		t.Fatalf("steps = %v, want %v", st.Steps, wantSteps)
	}
	if st.Probe != "ok" {
		t.Fatalf("probe = %q, want ok after a green re-probe", st.Probe)
	}
}

func TestRunBackoffAfterRedReprobe(t *testing.T) {
	dir := t.TempDir()
	desired := filepath.Join(dir, "desired.json")
	writeDesiredForTest(t, desired, Up)
	d := &Daemon{
		DesiredPath: desired,
		StatusPath:  filepath.Join(dir, "status.json"),
		Interval:    time.Second,
		Backoff:     7 * time.Second,
		Probe:       func(context.Context) error { return errors.New("still red") },
		Reconcile: func(_ context.Context, report func(string, error)) error {
			report("S4", errors.New("repair failed"))
			return errors.New("repair failed")
		},
	}
	slept := runCycles(t, d, 1)
	if len(slept) != 1 || slept[0] != 7*time.Second {
		t.Fatalf("sleep = %v, want Backoff after a red re-probe", slept)
	}
	st, err := ReadStatus(d.StatusPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Probe != "still red" {
		t.Fatalf("probe = %q, want the re-probe error", st.Probe)
	}
	if st.Steps["S4"] != "repair failed" {
		t.Fatalf("steps = %v, want S4=repair failed", st.Steps)
	}
}

func TestRunExitsWithCtxErr(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := &Daemon{
		DesiredPath: filepath.Join(dir, "desired.json"),
		StatusPath:  filepath.Join(dir, "status.json"),
		Probe: func(context.Context) error {
			t.Error("probe ran on a cancelled ctx")
			return nil
		},
		Reconcile: func(context.Context, func(string, error)) error {
			t.Error("reconcile ran on a cancelled ctx")
			return nil
		},
	}
	if err := d.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v, want context.Canceled", err)
	}
}

func TestRunUpCallsEachTickOncePerIteration(t *testing.T) {
	dir := t.TempDir()
	desired := filepath.Join(dir, "desired.json")
	writeDesiredForTest(t, desired, Up)
	ticks := 0
	d := &Daemon{
		DesiredPath: desired,
		StatusPath:  filepath.Join(dir, "status.json"),
		Probe:       func(context.Context) error { return nil },
		Reconcile: func(context.Context, func(string, error)) error {
			t.Error("reconcile must not run on a green probe")
			return nil
		},
		EachTick: func(context.Context) { ticks++ },
	}
	runCycles(t, d, 2)
	if ticks != 2 {
		t.Fatalf("EachTick ran %d times, want once per iteration (2)", ticks)
	}
}

func TestDesiredRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desired.json")
	for _, want := range []Desired{Up, Down} {
		if err := WriteDesired(path, want); err != nil {
			t.Fatal(err)
		}
		got, err := ReadDesired(path)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("ReadDesired = %q, want %q", got, want)
		}
	}
}

func TestReadDesiredMissingMeansDown(t *testing.T) {
	got, err := ReadDesired(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got != Down {
		t.Fatalf("missing desired file = %q, want down", got)
	}
}

func TestReadDesiredGarbageErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "desired.json")
	if err := os.WriteFile(path, []byte("sideways"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDesired(path); err == nil {
		t.Fatal("garbage desired must error, not be trusted")
	}
}

func TestStatusRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	in := Status{
		Desired:   Up,
		Steps:     map[string]string{"S1": "ok", "S5": "route 10.52.0.7 contested"},
		Probe:     "ok",
		Contested: []string{"10.52.0.7"},
		UpdatedAt: at,
	}
	if err := WriteStatus(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Desired != in.Desired || out.Probe != in.Probe || !out.UpdatedAt.Equal(at) ||
		!reflect.DeepEqual(out.Steps, in.Steps) || !reflect.DeepEqual(out.Contested, in.Contested) {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestReadStatusMissingErrors(t *testing.T) {
	if _, err := ReadStatus(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("missing status file must error so the CLI can print its fallback")
	}
}
