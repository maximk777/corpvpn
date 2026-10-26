package failure

import (
	"errors"
	"fmt"
	"testing"
)

func TestClassify(t *testing.T) {
	if got := Classify(nil); got != Infra {
		t.Errorf("Classify(nil) = %q, want %q", got, Infra)
	}
	if got := Classify(errors.New("ssh: connect refused")); got != Infra {
		t.Errorf("Classify(plain error) = %q, want %q", got, Infra)
	}
	if got := Classify(errors.New("dial tcp 10.0.0.1: i/o timeout")); got != Infra {
		t.Errorf("Classify(transport error) = %q, want %q", got, Infra)
	}
	if got := Classify(fmt.Errorf("%w: %v", ErrAuth, errors.New("шлюз отверг учётные данные"))); got != Auth {
		t.Errorf("Classify(wrapped ErrAuth) = %q, want %q", got, Auth)
	}
	// Wrapping must survive further layers of %w.
	inner := fmt.Errorf("%w: %v", ErrAuth, errors.New("login failed"))
	outer := fmt.Errorf("rebuild attempt 2: %w", inner)
	if got := Classify(outer); got != Auth {
		t.Errorf("Classify(double wrapped) = %q, want %q", got, Auth)
	}
}

func TestIsAuthFailureText(t *testing.T) {
	// Positive samples: one per alternative carried over from connect.go
	// (reAuthFail) and ovpn.go (reOvpnFail).
	positive := []string{
		// reAuthFail
		"Login failed",
		">ERROR: Authentication failed",
		"Invalid credentials provided",
		"Permission denied (publickey).",
		// reOvpnFail
		"AUTH_FAILED",
		"Password verification failed",
		"Cannot load private key file",
		"private key verification failed",
	}
	for _, s := range positive {
		if !IsAuthFailureText(s) {
			t.Errorf("IsAuthFailureText(%q) = false, want true", s)
		}
	}

	negative := []string{
		"connection refused",
		"dial tcp: i/o timeout",
		"CSTP connected",
		"Configured as 10.195.0.6",
		"session closed before tunnel came up",
	}
	for _, s := range negative {
		if IsAuthFailureText(s) {
			t.Errorf("IsAuthFailureText(%q) = true, want false", s)
		}
	}
}
