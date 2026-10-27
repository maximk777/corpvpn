package dnsfwd

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// startUpstream runs a fake corp DNS server on localhost. handler builds
// the raw response for each raw query; returning nil sends nothing. The
// returned counter counts received queries.
func startUpstream(t *testing.T, handler func(query []byte) []byte) (string, *atomic.Int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	var hits atomic.Int32
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			hits.Add(1)
			if resp := handler(append([]byte(nil), buf[:n]...)); resp != nil {
				pc.WriteTo(resp, from)
			}
		}
	}()
	return pc.LocalAddr().String(), &hits
}

// cannedAHandler answers every query with a canned A record.
func cannedAHandler(name string, addr [4]byte) func([]byte) []byte {
	return func(query []byte) []byte {
		var q dnsmessage.Message
		if err := q.Unpack(query); err != nil {
			return nil
		}
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true},
			Questions: q.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName(name),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: addr},
			}},
		}
		out, err := resp.Pack()
		if err != nil {
			return nil
		}
		return out
	}
}

// startForwarder serves f on an ephemeral localhost port and returns the
// address. Cleanup cancels the context and requires ServeUDP to return.
func startForwarder(t *testing.T, f *Forwarder) string {
	t.Helper()
	addr := func() string {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve port: %v", err)
		}
		defer pc.Close()
		return pc.LocalAddr().String()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- f.ServeUDP(ctx, addr) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("ServeUDP: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("ServeUDP did not return after context cancel")
		}
	})
	return addr
}

// exchange sends query to the forwarder and unpacks the reply. It retries
// for a few seconds because the first datagram right after ServeUDP start
// may hit a not-yet-bound port.
func exchange(t *testing.T, addr string, query []byte) dnsmessage.Message {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := conn.Write(query); err == nil {
			buf := make([]byte, 1500)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, err := conn.Read(buf)
			if err == nil {
				var m dnsmessage.Message
				if err := m.Unpack(buf[:n]); err != nil {
					t.Fatalf("unpack reply: %v", err)
				}
				return m
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no reply from forwarder in time")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func buildQuery(id uint16, name string, typ dnsmessage.Type) []byte {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(name),
			Type:  typ,
			Class: dnsmessage.ClassINET,
		}},
	}
	out, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return out
}

func hasARecord(t *testing.T, m dnsmessage.Message) ([4]byte, bool) {
	t.Helper()
	for _, rr := range m.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			return a.A, true
		}
	}
	return [4]byte{}, false
}

// logCollector captures the forwarder logger output.
type logCollector struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCollector) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, string(p))
	return len(p), nil
}

func (l *logCollector) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "")
}

func TestBankAQueryForwardsToUpstream(t *testing.T) {
	upAddr, hits := startUpstream(t, cannedAHandler("wiki.wb-bank.ru.", [4]byte{10, 15, 0, 64}))

	var mu sync.Mutex
	var answered []string
	f := &Forwarder{
		BankDomain: "wb-bank.ru",
		Upstream:   upAddr,
		OnAnswer: func(host string, addr [4]byte) {
			mu.Lock()
			defer mu.Unlock()
			answered = append(answered, host)
		},
	}
	fwdAddr := startForwarder(t, f)

	m := exchange(t, fwdAddr, buildQuery(0x1234, "wiki.wb-bank.ru.", dnsmessage.TypeA))
	if m.ID != 0x1234 {
		t.Errorf("reply ID = %#x, want 0x1234", m.ID)
	}
	if m.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v, want success", m.RCode)
	}
	addr, ok := hasARecord(t, m)
	if !ok {
		t.Fatal("reply has no A record")
	}
	if addr != [4]byte{10, 15, 0, 64} {
		t.Errorf("A = %v, want 10.15.0.64", addr)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(answered) != 1 || answered[0] != "wiki.wb-bank.ru" {
		t.Errorf("OnAnswer hosts = %v, want [wiki.wb-bank.ru]", answered)
	}
}

func TestBankAAAAForwardsWithoutOnAnswer(t *testing.T) {
	upAddr, hits := startUpstream(t, func(query []byte) []byte {
		var q dnsmessage.Message
		if err := q.Unpack(query); err != nil {
			return nil
		}
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: q.ID, Response: true},
			Questions: q.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("wiki.wb-bank.ru."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
			}},
		}
		out, err := resp.Pack()
		if err != nil {
			return nil
		}
		return out
	})

	var called atomic.Bool
	f := &Forwarder{
		BankDomain: "wb-bank.ru",
		Upstream:   upAddr,
		OnAnswer:   func(string, [4]byte) { called.Store(true) },
	}
	fwdAddr := startForwarder(t, f)

	m := exchange(t, fwdAddr, buildQuery(2, "wiki.wb-bank.ru.", dnsmessage.TypeAAAA))
	if m.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("rcode = %v, want success", m.RCode)
	}
	for _, rr := range m.Answers {
		if _, ok := rr.Body.(*dnsmessage.AAAAResource); !ok {
			t.Errorf("answer body %T, want AAAAResource", rr.Body)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1", got)
	}
	if called.Load() {
		t.Error("OnAnswer fired for AAAA answer, want no call")
	}
}

func TestForeignDomainRefusedWithoutUpstream(t *testing.T) {
	upAddr, hits := startUpstream(t, func([]byte) []byte { return nil })

	f := &Forwarder{BankDomain: "wb-bank.ru", Upstream: upAddr}
	fwdAddr := startForwarder(t, f)

	// A query for a name outside the bank domain.
	m := exchange(t, fwdAddr, buildQuery(3, "example.com.", dnsmessage.TypeA))
	if m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("rcode for example.com = %v, want NameError", m.RCode)
	}
	// Non-A/AAAA query type for a bank name must also be refused without upstream.
	m = exchange(t, fwdAddr, buildQuery(4, "wiki.wb-bank.ru.", dnsmessage.TypeTXT))
	if m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("rcode for TXT = %v, want NameError", m.RCode)
	}
	if got := hits.Load(); got != 0 {
		t.Errorf("upstream hits = %d, want 0", got)
	}
}

func TestGarbageDoesNotKillLoop(t *testing.T) {
	upAddr, hits := startUpstream(t, cannedAHandler("wiki.wb-bank.ru.", [4]byte{10, 15, 0, 64}))

	logs := &logCollector{}
	f := &Forwarder{BankDomain: "wb-bank.ru", Upstream: upAddr, Logger: log.New(logs, "", 0)}
	fwdAddr := startForwarder(t, f)

	// Malformed datagrams must be logged and skipped.
	conn, err := net.Dial("udp", fwdAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	for _, pkt := range [][]byte{{0xff}, {0, 1, 2, 3}, []byte("not a dns packet")} {
		if _, err := conn.Write(pkt); err != nil {
			t.Fatalf("write garbage: %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	m := exchange(t, fwdAddr, buildQuery(5, "wiki.wb-bank.ru.", dnsmessage.TypeA))
	if m.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("after garbage rcode = %v, want success", m.RCode)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1", got)
	}
	if out := logs.all(); !strings.Contains(out, "malformed") {
		t.Errorf("logger output %q, want it to mention malformed packet", out)
	}
}

func TestUpstreamTimeoutYieldsServfail(t *testing.T) {
	// Black hole: bound UDP socket that never answers.
	blackHole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("black hole listen: %v", err)
	}
	defer blackHole.Close()

	f := &Forwarder{BankDomain: "wb-bank.ru", Upstream: blackHole.LocalAddr().String()}
	fwdAddr := startForwarder(t, f)

	m := exchange(t, fwdAddr, buildQuery(6, "wiki.wb-bank.ru.", dnsmessage.TypeA))
	if m.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("rcode = %v, want SERVFAIL", m.RCode)
	}
}

// TestServeUDPServesForeignQueryOnEphemeralPort exercises the SO_REUSEADDR
// ListenConfig listen path (added to coexist with macOS mDNSResponder's
// wildcard *.53 bind) directly: ServeUDP on an ephemeral port must still
// answer a foreign-name query with NXDOMAIN, no upstream contacted.
func TestServeUDPServesForeignQueryOnEphemeralPort(t *testing.T) {
	// Reserve an ephemeral port so the test knows where to send; serving on
	// it goes through the same ListenConfig path as 127.0.0.1:53.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	f := &Forwarder{BankDomain: "wb-bank.ru"}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- f.ServeUDP(ctx, addr) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("ServeUDP: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("ServeUDP did not return after context cancel")
		}
	})

	m := exchange(t, addr, buildQuery(7, "example.com.", dnsmessage.TypeA))
	if m.RCode != dnsmessage.RCodeNameError {
		t.Errorf("rcode for example.com = %v, want NameError", m.RCode)
	}
}

func TestUnderBankDomain(t *testing.T) {
	f := &Forwarder{BankDomain: "wb-bank.ru"}
	cases := []struct {
		name string
		want bool
	}{
		{"wiki.wb-bank.ru.", true},
		{"wb-bank.ru.", true},
		{"wiki.wb-bank.ru", true},
		{"WIKI.WB-BANK.RU.", true},
		{"example.com.", false},
		{"notwb-bank.ru.", false},
		{"wb-bank.ru.example.com.", false},
		{"", false},
	}
	for _, c := range cases {
		if got := f.underBankDomain(c.name); got != c.want {
			t.Errorf("underBankDomain(%q) = %v, want %v", c.name, got, c.want)
		}
	}
	if f := (&Forwarder{}); f.underBankDomain("wb-bank.ru.") {
		t.Error("empty BankDomain must match nothing")
	}
}
