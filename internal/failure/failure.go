// Package failure classifies reconcile errors as auth or infra.
// Auth means the gateway rejected credentials; infra is everything else.
package failure

import (
	"errors"
	"regexp"
)

var ErrAuth = errors.New("gateway rejected credentials")

type Class string

const (
	Auth  Class = "auth"
	Infra Class = "infra"
)

// Patterns mirror reAuthFail in connect.go and reOvpnFail in ovpn.go:
// keep them in sync if those change.
var (
	reAuthFail = regexp.MustCompile(`(?i)(login failed|authentication failed|invalid credentials|permission denied)`)
	reOvpnFail = regexp.MustCompile(`(?i)(auth_failed|password verification failed|cannot load|private key.*fail)`)
)

// Classify maps an error to its class; nil maps to Infra (caller checks nil first).
func Classify(err error) Class {
	if errors.Is(err, ErrAuth) {
		return Auth
	}
	return Infra
}

// IsAuthFailureText reports whether gateway pty output matches a login
// rejection. Patterns mirror the ones connect.go uses (reAuthFail) and
// ovpn.go (reOvpnFail): keep them in sync if those change.
func IsAuthFailureText(s string) bool {
	return reAuthFail.MatchString(s) || reOvpnFail.MatchString(s)
}
