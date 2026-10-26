package verbs

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestResolverKick(t *testing.T) {
	type call struct {
		name string
		args []string
	}

	t.Run("killall success does not escalate", func(t *testing.T) {
		var calls []call
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			calls = append(calls, call{name: name, args: args})
			return "", nil
		}
		if err := ResolverKick(run); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []call{{name: "killall", args: []string{"mDNSResponder"}}}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("calls = %v, want %v", calls, want)
		}
	})

	t.Run("missing killall escalates to launchctl kickstart in order", func(t *testing.T) {
		var calls []call
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			calls = append(calls, call{name: name, args: args})
			if name == "killall" {
				return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
			}
			return "", nil
		}
		if err := ResolverKick(run); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []call{
			{name: "killall", args: []string{"mDNSResponder"}},
			{name: "launchctl", args: []string{"kickstart", "-k", "system/com.apple.mDNSResponder"}},
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("calls = %v, want %v", calls, want)
		}
	})

	t.Run("kickstart failure surfaces", func(t *testing.T) {
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			if name == "killall" {
				return "", &exec.Error{Name: name, Err: exec.ErrNotFound}
			}
			return "Launch has not been started", errors.New("exit status 3")
		}
		if err := ResolverKick(run); err == nil {
			t.Fatal("want kickstart error, got nil")
		}
	})

	t.Run("other killall failures do not escalate", func(t *testing.T) {
		calls := 0
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			calls++
			return "signal error", errors.New("exit status 1")
		}
		if err := ResolverKick(run); err == nil {
			t.Fatal("want killall error, got nil")
		}
		if calls != 1 {
			t.Fatalf("want a single call, got %d", calls)
		}
	})

	t.Run("a missing process is fine", func(t *testing.T) {
		calls := 0
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			calls++
			return "No matching processes belonging to you were found", errors.New("exit status 1")
		}
		if err := ResolverKick(run); err != nil {
			t.Fatalf("missing process must not error, got %v", err)
		}
		if calls != 1 {
			t.Fatalf("want a single call, got %d", calls)
		}
	})
}

func TestResolverScopedLookup(t *testing.T) {
	const wantArgsPrefix = "-q host -a name"

	t.Run("answer block is true", func(t *testing.T) {
		var got []string
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			got = append([]string{name}, args...)
			return "name: btg.wb-bank.ru\nip_address: 10.15.0.64\n", nil
		}
		if !ScopedLookupWorks(context.Background(), run, "btg.wb-bank.ru") {
			t.Fatal("want true on an answer block")
		}
		want := []string{"dscacheutil", "-q", "host", "-a", "name", "btg.wb-bank.ru"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("args = %v, want %v", got, want)
		}
	})

	t.Run("name line followed by an address is true", func(t *testing.T) {
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			return "name: btg.wb-bank.ru\naddress: 10.15.0.64\n", nil
		}
		if !ScopedLookupWorks(context.Background(), run, "btg.wb-bank.ru") {
			t.Fatal("want true when an address line follows name:")
		}
	})

	t.Run("name without a following address is false", func(t *testing.T) {
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			return "name: btg.wb-bank.ru\n", nil
		}
		if ScopedLookupWorks(context.Background(), run, "btg.wb-bank.ru") {
			t.Fatal("want false without an address line")
		}
	})

	t.Run("empty output is false", func(t *testing.T) {
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			return "", nil
		}
		if ScopedLookupWorks(context.Background(), run, "btg.wb-bank.ru") {
			t.Fatal("want false on empty output")
		}
	})

	t.Run("runner error is false", func(t *testing.T) {
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			return "name: x\nip_address: 10.15.0.64\n", errors.New("signal killed")
		}
		if ScopedLookupWorks(context.Background(), run, "btg.wb-bank.ru") {
			t.Fatal("want false on runner error")
		}
	})

	t.Run("runner receives a 6s deadline context", func(t *testing.T) {
		run := func(ctx context.Context, name string, args ...string) (string, error) {
			d, ok := ctx.Deadline()
			if !ok {
				t.Error("runner got a context without a deadline")
			} else if left := time.Until(d); left <= 0 || left > 6*time.Second {
				t.Errorf("deadline in %v, want within 6s", left)
			}
			if joined := strings.Join(args, " "); !strings.HasPrefix(joined, wantArgsPrefix) {
				t.Errorf("args = %q", joined)
			}
			return "name: x\nip_address: 10.15.0.64\n", nil
		}
		if !ScopedLookupWorks(context.Background(), run, "btg.wb-bank.ru") {
			t.Fatal("want true on an answer block")
		}
	})
}
