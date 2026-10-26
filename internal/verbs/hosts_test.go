package verbs

import (
	"os"
	"strings"
	"testing"
)

// hostsMem is an in-memory hosts file backing the readFile/writeFile seams.
// missing=true makes read report os.ErrNotExist.
type hostsMem struct {
	data     []byte
	missing  bool
	writes   int
	lastMode os.FileMode
}

func (f *hostsMem) read(string) ([]byte, error) {
	if f.missing {
		return nil, os.ErrNotExist
	}
	return f.data, nil
}

func (f *hostsMem) write(_ string, b []byte, m os.FileMode) error {
	f.writes++
	f.data = append([]byte(nil), b...)
	f.lastMode = m
	return nil
}

func wantBlock(entries ...string) string {
	return "# >>> corpvpn managed >>>\n" + strings.Join(entries, "\n") + "\n" + "# <<< corpvpn managed <<<\n"
}

func TestHostsUp(t *testing.T) {
	t.Run("missing file is created with just the block", func(t *testing.T) {
		f := &hostsMem{missing: true}
		err := HostsUp("/etc/hosts", []HostsEntry{{Addr: "10.15.0.64", Name: "btg.wb-bank.ru"}}, f.read, f.write)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := wantBlock("10.15.0.64 btg.wb-bank.ru")
		if string(f.data) != want {
			t.Fatalf("data = %q, want %q", f.data, want)
		}
		if f.writes != 1 {
			t.Fatalf("writes = %d, want 1", f.writes)
		}
		if f.lastMode != 0o644 {
			t.Fatalf("mode = %o, want 644", f.lastMode)
		}
	})

	t.Run("existing file without markers gets the block appended", func(t *testing.T) {
		f := &hostsMem{data: []byte("127.0.0.1 localhost\n")}
		err := HostsUp("/etc/hosts", []HostsEntry{{Addr: "10.15.0.64", Name: "btg.wb-bank.ru"}}, f.read, f.write)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "127.0.0.1 localhost\n" + wantBlock("10.15.0.64 btg.wb-bank.ru")
		if string(f.data) != want {
			t.Fatalf("data = %q, want %q", f.data, want)
		}
	})

	t.Run("file without trailing newline keeps original bytes and gains the block", func(t *testing.T) {
		f := &hostsMem{data: []byte("127.0.0.1 localhost")}
		err := HostsUp("/etc/hosts", []HostsEntry{{Addr: "10.15.0.64", Name: "btg.wb-bank.ru"}}, f.read, f.write)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "127.0.0.1 localhost\n" + wantBlock("10.15.0.64 btg.wb-bank.ru")
		if string(f.data) != want {
			t.Fatalf("data = %q, want %q", f.data, want)
		}
	})

	t.Run("existing block is replaced in place", func(t *testing.T) {
		f := &hostsMem{data: []byte("a\n" + wantBlock("10.0.0.1 old.wb-bank.ru") + "b\n")}
		err := HostsUp("/etc/hosts", []HostsEntry{{Addr: "10.15.0.64", Name: "btg.wb-bank.ru"}}, f.read, f.write)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "a\n" + wantBlock("10.15.0.64 btg.wb-bank.ru") + "b\n"
		if string(f.data) != want {
			t.Fatalf("data = %q, want %q", f.data, want)
		}
	})

	t.Run("duplicate names keep the last entry", func(t *testing.T) {
		f := &hostsMem{data: []byte("127.0.0.1 localhost\n")}
		entries := []HostsEntry{
			{Addr: "10.15.0.64", Name: "btg.wb-bank.ru"},
			{Addr: "10.15.0.65", Name: "btg.wb-bank.ru"},
		}
		err := HostsUp("/etc/hosts", entries, f.read, f.write)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "127.0.0.1 localhost\n" + wantBlock("10.15.0.65 btg.wb-bank.ru")
		if string(f.data) != want {
			t.Fatalf("data = %q, want %q", f.data, want)
		}
	})

	t.Run("same entries again is a no-op write", func(t *testing.T) {
		f := &hostsMem{data: []byte(wantBlock("10.15.0.64 btg.wb-bank.ru"))}
		err := HostsUp("/etc/hosts", []HostsEntry{{Addr: "10.15.0.64", Name: "btg.wb-bank.ru"}}, f.read, f.write)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f.writes != 0 {
			t.Fatalf("writes = %d, want 0 (idempotent)", f.writes)
		}
	})
}

func TestHostsDown(t *testing.T) {
	t.Run("removes the block and leaves the rest", func(t *testing.T) {
		f := &hostsMem{data: []byte("a\n" + wantBlock("10.15.0.64 btg.wb-bank.ru") + "b\n")}
		err := HostsDown("/etc/hosts", f.read, f.write)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(f.data) != "a\nb\n" {
			t.Fatalf("data = %q, want %q", f.data, "a\nb\n")
		}
	})

	t.Run("removes a block at end of file", func(t *testing.T) {
		f := &hostsMem{data: []byte("127.0.0.1 localhost\n" + wantBlock("10.15.0.64 btg.wb-bank.ru"))}
		err := HostsDown("/etc/hosts", f.read, f.write)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(f.data) != "127.0.0.1 localhost\n" {
			t.Fatalf("data = %q, want %q", f.data, "127.0.0.1 localhost\n")
		}
	})

	t.Run("no block leaves the file byte-identical", func(t *testing.T) {
		f := &hostsMem{data: []byte("127.0.0.1 localhost\n")}
		err := HostsDown("/etc/hosts", f.read, f.write)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(f.data) != "127.0.0.1 localhost\n" {
			t.Fatalf("data = %q, want byte-identical", f.data)
		}
		if f.writes != 0 {
			t.Fatalf("writes = %d, want 0", f.writes)
		}
	})

	t.Run("missing file is a no-op", func(t *testing.T) {
		f := &hostsMem{missing: true}
		err := HostsDown("/etc/hosts", f.read, f.write)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if f.writes != 0 {
			t.Fatalf("writes = %d, want 0", f.writes)
		}
	})
}
