package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Desired is the persisted user intent: "up" or "down".
type Desired string

// Desired states stored in desired.json.
const (
	Up   Desired = "up"
	Down Desired = "down"
)

// ReadDesired reads desired.json; missing file means down.
func ReadDesired(path string) (Desired, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Down, nil
	}
	if err != nil {
		return "", err
	}
	v := Desired(strings.TrimSpace(string(data)))
	switch v {
	case "", Down: // an empty file carries no intent; same as missing
		return Down, nil
	case Up:
		return Up, nil
	default:
		// Corrupt desired state must error rather than be trusted.
		return "", fmt.Errorf("desired: unknown value %q in %s", v, path)
	}
}

// WriteDesired persists the desired state.
func WriteDesired(path string, d Desired) error {
	return os.WriteFile(path, []byte(d), 0o644)
}

// Status is what the status command renders.
type Status struct {
	Desired   Desired           `json:"desired"`
	Steps     map[string]string `json:"steps"` // step name -> ok/failed reason
	Probe     string            `json:"probe"` // "ok" | last error
	Contested []string          `json:"contested"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// WriteStatus persists the status file.
func WriteStatus(path string, s Status) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ReadStatus reads the status file; a missing file is an error so the
// CLI can print its fallback.
func ReadStatus(path string) (Status, error) {
	var s Status
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, err
	}
	return s, nil
}
