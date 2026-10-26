// Package reconcile runs ordered idempotent steps toward the desired state.
package reconcile

import (
	"context"

	"corpvpn/internal/failure"
)

type Step struct {
	Name   string
	Ensure func(ctx context.Context) error
	Verify func(ctx context.Context) error
}

type Result struct {
	Healthy  bool
	BrokenAt string        // step name of the first failed verify, "" if healthy
	Class    failure.Class // class of the repair error, "" if healthy or not yet repaired
	Err      error
}

// VerifyAll returns the name of the first step whose verify fails, "" if all pass.
func VerifyAll(ctx context.Context, steps []Step) (string, error) {
	for _, s := range steps {
		if err := s.Verify(ctx); err != nil {
			return s.Name, err
		}
	}
	return "", nil
}

// RepairFrom ensures the step named firstBroken and every step after it,
// verifying each after its ensure. Stops at the first error, returning the
// step name and a classified error.
func RepairFrom(ctx context.Context, steps []Step, firstBroken string) (broken string, class failure.Class, err error) {
	start := 0
	for i, s := range steps {
		if s.Name == firstBroken {
			start = i
			break
		}
	}
	for _, s := range steps[start:] {
		if err := s.Ensure(ctx); err != nil {
			return s.Name, failure.Classify(err), err
		}
		if err := s.Verify(ctx); err != nil {
			return s.Name, failure.Classify(err), err
		}
	}
	return "", "", nil
}
