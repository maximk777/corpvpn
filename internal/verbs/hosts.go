package verbs

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// The managed hosts block is bounded by these exact marker lines.
const (
	hostsStartMarker = "# >>> corpvpn managed >>>"
	hostsEndMarker   = "# <<< corpvpn managed <<<"
	hostsFileMode    = 0o644
)

type HostsEntry struct {
	Addr string // "10.15.0.64"
	Name string // "btg.wb-bank.ru"
}

// HostsUp rewrites the hosts file at path so that the managed block contains
// exactly entries; content outside the block is preserved byte-for-byte.
// Missing file or missing markers are fine: the block is appended at the end
// (markers included) on first write. file ops go through the injectable
// reader/writer funcs.
func HostsUp(path string, entries []HostsEntry, readFile func(string) ([]byte, error), writeFile func(string, []byte, os.FileMode) error) error {
	orig, err := readFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("hosts: read %s: %w", path, err)
		}
		orig = nil
	}
	s := string(orig)
	start, end, found, err := findHostsBlock(s)
	if err != nil {
		return err
	}
	block := renderHostsBlock(entries)
	var updated string
	switch {
	case found:
		updated = s[:start] + block + s[end:]
	case s == "" || strings.HasSuffix(s, "\n"):
		updated = s + block
	default:
		// Separator newline so the start marker does not glue to a last
		// line lacking one; the original bytes stay intact.
		updated = s + "\n" + block
	}
	if updated == s {
		return nil
	}
	if err := writeFile(path, []byte(updated), hostsFileMode); err != nil {
		return fmt.Errorf("hosts: write %s: %w", path, err)
	}
	return nil
}

// HostsDown removes the managed block (markers included), preserving the
// rest. No block: no-op (no write).
func HostsDown(path string, readFile func(string) ([]byte, error), writeFile func(string, []byte, os.FileMode) error) error {
	orig, err := readFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("hosts: read %s: %w", path, err)
	}
	s := string(orig)
	start, end, found, err := findHostsBlock(s)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	updated := s[:start] + s[end:]
	if err := writeFile(path, []byte(updated), hostsFileMode); err != nil {
		return fmt.Errorf("hosts: write %s: %w", path, err)
	}
	return nil
}

// renderHostsBlock renders the block in canonical form: every line including
// the end marker is newline-terminated. Duplicate names keep the last entry.
func renderHostsBlock(entries []HostsEntry) string {
	kept := make([]HostsEntry, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		if seen[entries[i].Name] {
			continue
		}
		seen[entries[i].Name] = true
		kept = append(kept, entries[i])
	}
	var b strings.Builder
	b.WriteString(hostsStartMarker)
	b.WriteByte('\n')
	for i := len(kept) - 1; i >= 0; i-- {
		b.WriteString(kept[i].Addr)
		b.WriteByte(' ')
		b.WriteString(kept[i].Name)
		b.WriteByte('\n')
	}
	b.WriteString(hostsEndMarker)
	b.WriteByte('\n')
	return b.String()
}

// findHostsBlock locates the block as whole marker lines. It returns the
// byte range [start, end) covering the start marker through the end marker's
// newline (or end of file). found=false means no block. A start marker
// without a closing end marker is corrupt: refuse to touch the file.
func findHostsBlock(s string) (start, end int, found bool, err error) {
	lineStart := 0
	inBlock := false
	for {
		nl := strings.IndexByte(s[lineStart:], '\n')
		contentEnd := len(s)
		hasNL := nl >= 0
		if hasNL {
			contentEnd = lineStart + nl
		}
		line := strings.TrimSuffix(s[lineStart:contentEnd], "\r")
		switch {
		case !inBlock && line == hostsStartMarker:
			inBlock = true
			start = lineStart
		case inBlock && line == hostsEndMarker:
			if hasNL {
				return start, contentEnd + 1, true, nil
			}
			return start, len(s), true, nil
		}
		if !hasNL {
			break
		}
		lineStart = contentEnd + 1
	}
	if inBlock {
		return 0, 0, false, fmt.Errorf("hosts: %s without %s", hostsStartMarker, hostsEndMarker)
	}
	return 0, 0, false, nil
}
