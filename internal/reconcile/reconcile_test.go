package reconcile

import (
	"context"
	"errors"
	"slices"
	"testing"

	"corpvpn/internal/failure"
)

// fakeSteps builds n steps named S1..Sn. Every ensure and verify invocation
// appends "<name>.ensure"/"<name>.verify" to calls and records the ctx it
// received. verifyErr[name] makes verify fail until ensure ran for that step
// (ensure repairs the breakage); ensureErr[name] always fails ensure.
func fakeSteps(n int, calls *[]string, ctxs *[]context.Context, ensureErr, verifyErr map[string]error) []Step {
	ensured := map[string]bool{}
	steps := make([]Step, n)
	for i := range n {
		name := stepName(i)
		steps[i] = Step{
			Name: name,
			Ensure: func(ctx context.Context) error {
				*calls = append(*calls, name+".ensure")
				if ctxs != nil {
					*ctxs = append(*ctxs, ctx)
				}
				ensured[name] = true
				if err, ok := ensureErr[name]; ok {
					return err
				}
				return nil
			},
			Verify: func(ctx context.Context) error {
				*calls = append(*calls, name+".verify")
				if ctxs != nil {
					*ctxs = append(*ctxs, ctx)
				}
				if !ensured[name] {
					if err, ok := verifyErr[name]; ok {
						return err
					}
				}
				return nil
			},
		}
	}
	return steps
}

func stepName(i int) string { return "S" + string(rune('1'+i)) }

func TestVerifyAllAllHealthy(t *testing.T) {
	var calls []string
	steps := fakeSteps(6, &calls, nil, nil, nil)

	broken, err := VerifyAll(context.Background(), steps)
	if err != nil {
		t.Fatalf("VerifyAll returned error %v, want nil", err)
	}
	if broken != "" {
		t.Fatalf("VerifyAll broken = %q, want \"\"", broken)
	}
	// VerifyAll must not repair anything: ensure is never invoked.
	for _, c := range calls {
		if c[len(c)-len(".ensure"):] == ".ensure" {
			t.Fatalf("VerifyAll invoked ensure: %v", calls)
		}
	}
	// Nothing broken, so no RepairFrom call would follow; the repair flow
	// (firstBroken != "" guard) is covered by TestRepairFrom* tests.
}

func TestRepairFromS2Broken(t *testing.T) {
	var calls []string
	var ctxs []context.Context
	steps := fakeSteps(4, &calls, &ctxs, nil, map[string]error{"S2": errors.New("socks down")})

	broken, err := VerifyAll(context.Background(), steps)
	if broken != "S2" || err == nil {
		t.Fatalf("VerifyAll = (%q, %v), want (\"S2\", error)", broken, err)
	}

	calls = nil
	repairBroken, class, err := RepairFrom(context.Background(), steps, broken)
	if err != nil {
		t.Fatalf("RepairFrom returned error %v, want nil", err)
	}
	if repairBroken != "" {
		t.Fatalf("RepairFrom broken = %q, want \"\"", repairBroken)
	}
	if class != "" {
		t.Fatalf("RepairFrom class = %q, want \"\"", class)
	}

	want := []string{
		"S2.ensure", "S2.verify",
		"S3.ensure", "S3.verify",
		"S4.ensure", "S4.verify",
	}
	if !slices.Equal(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	if slices.Contains(calls, "S1.ensure") || slices.Contains(calls, "S1.verify") {
		t.Fatalf("steps before firstBroken were touched: %v", calls)
	}
}

func TestRepairFromEnsureErrorAtS3(t *testing.T) {
	var calls []string
	authErr := failure.ErrAuth
	steps := fakeSteps(4, &calls, nil,
		map[string]error{"S3": authErr},
		map[string]error{"S2": errors.New("socks down")})

	broken, class, err := RepairFrom(context.Background(), steps, "S2")
	if broken != "S3" {
		t.Fatalf("RepairFrom broken = %q, want \"S3\"", broken)
	}
	if !errors.Is(err, authErr) {
		t.Fatalf("RepairFrom err = %v, want ErrAuth", err)
	}
	if class != failure.Auth {
		t.Fatalf("RepairFrom class = %q, want %q", class, failure.Auth)
	}

	want := []string{"S2.ensure", "S2.verify", "S3.ensure"}
	if !slices.Equal(calls, want) {
		t.Fatalf("calls = %v, want %v (cascade must stop at S3)", calls, want)
	}
	if slices.Contains(calls, "S4.ensure") || slices.Contains(calls, "S4.verify") {
		t.Fatalf("cascade continued past failing step: %v", calls)
	}
}

func TestRepairFromCtxPassedThrough(t *testing.T) {
	var calls []string
	var ctxs []context.Context
	steps := fakeSteps(3, &calls, &ctxs, nil, map[string]error{"S1": errors.New("vm down")})

	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "probe")
	if _, _, err := RepairFrom(ctx, steps, "S1"); err != nil {
		t.Fatalf("RepairFrom returned error %v, want nil", err)
	}
	if len(ctxs) == 0 {
		t.Fatal("no ensure/verify invocations recorded")
	}
	for i, got := range ctxs {
		if got != ctx {
			t.Fatalf("call %d (%s) received a different ctx", i, calls[i])
		}
	}
}

func TestRepairFromVerifyErrorClassifiedInfra(t *testing.T) {
	var calls []string
	// A step whose ensure succeeds but never fixes the breakage: verify keeps
	// failing, and the repair reports that verify error as infra.
	s2 := Step{
		Name:   "S2",
		Ensure: func(context.Context) error { return nil },
		Verify: func(context.Context) error { return errors.New("route add failed") },
	}
	steps := fakeSteps(1, &calls, nil, nil, nil)
	steps = append(steps, s2)

	broken, class, err := RepairFrom(context.Background(), steps, "S2")
	if broken != "S2" || err == nil {
		t.Fatalf("RepairFrom = (%q, %v), want (\"S2\", error)", broken, err)
	}
	if class != failure.Infra {
		t.Fatalf("RepairFrom class = %q, want %q", class, failure.Infra)
	}
}
