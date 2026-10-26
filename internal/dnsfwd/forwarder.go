// Package dnsfwd implements the scoped DNS forwarder that serves the bank
// domain on 127.0.0.1:53 and refuses everything else.
package dnsfwd

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// upstreamTimeout bounds one upstream query; expiring yields SERVFAIL
// to the client rather than silence.
const upstreamTimeout = 2 * time.Second

// Forwarder answers only names under the bank domain, forwarding them
// to corp DNS. Every answered A record is reported to sink.
type Forwarder struct {
	BankDomain string // "wb-bank.ru", no leading dot
	Upstream   string // corp DNS "10.108.67.4:53" style
	// OnAnswer is called for every forwarded A answer (host, addr).
	OnAnswer func(host string, addr [4]byte)

	// Logger receives malformed-packet and upstream errors; nil discards.
	Logger *log.Logger
}

func (f *Forwarder) logf(format string, args ...any) {
	if f.Logger != nil {
		f.Logger.Printf(format, args...)
	}
}

// ServeUDP blocks serving one UDP listener on addr (e.g. "127.0.0.1:53").
// A malformed datagram is logged and skipped, never fatal. It returns nil
// once ctx is cancelled.
func (f *Forwarder) ServeUDP(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("dnsfwd: listen %s: %w", addr, err)
	}
	defer pc.Close()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()

	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("dnsfwd: read: %w", err)
		}
		pkt := append([]byte(nil), buf[:n]...)
		// Each packet in its own goroutine: one slow upstream query
		// (up to upstreamTimeout) must not stall other clients.
		go func() {
			if err := f.handlePacket(ctx, pc, from, pkt); err != nil {
				f.logf("dnsfwd: %v", err)
			}
		}()
	}
}

func (f *Forwarder) handlePacket(ctx context.Context, pc net.PacketConn, from net.Addr, pkt []byte) error {
	var q dnsmessage.Message
	if err := q.Unpack(pkt); err != nil {
		return fmt.Errorf("malformed query from %s: %w", from, err)
	}
	if len(q.Questions) == 0 {
		return fmt.Errorf("malformed query from %s: no questions", from)
	}
	question := q.Questions[0]
	name := question.Name.String()

	if !f.underBankDomain(name) || (question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA) {
		return f.reply(pc, from, stubAnswer(q, dnsmessage.RCodeNameError))
	}

	ans, err := f.forward(ctx, pkt)
	if err != nil {
		f.logf("dnsfwd: upstream %s: %v", f.Upstream, err)
		return f.reply(pc, from, stubAnswer(q, dnsmessage.RCodeServerFailure))
	}
	f.reportA(name, ans)
	_, err = pc.WriteTo(ans, from)
	return err
}

// stubAnswer builds an empty response carrying only the rcode; upstream
// is never contacted on this path.
func stubAnswer(q dnsmessage.Message, rcode dnsmessage.RCode) dnsmessage.Message {
	return dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               q.ID,
			Response:         true,
			RecursionDesired: q.RecursionDesired,
			RCode:            rcode,
		},
		Questions: q.Questions,
	}
}

func (f *Forwarder) reply(pc net.PacketConn, from net.Addr, m dnsmessage.Message) error {
	buf, err := m.Pack()
	if err != nil {
		return fmt.Errorf("pack reply: %w", err)
	}
	_, err = pc.WriteTo(buf, from)
	return err
}

// underBankDomain reports whether name is within f.BankDomain.
// Comparison is case-insensitive; a trailing dot is tolerated. A name
// merely ending in the domain as a suffix ("notwb-bank.ru") does not match.
func (f *Forwarder) underBankDomain(name string) bool {
	if f.BankDomain == "" {
		return false
	}
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	d := strings.ToLower(strings.TrimSuffix(f.BankDomain, "."))
	return n == d || strings.HasSuffix(n, "."+d)
}

// forward sends the raw query to f.Upstream and returns the raw answer.
// The socket is fresh per query, so the first datagram back belongs to
// this query and ID matching comes for free.
func (f *Forwarder) forward(ctx context.Context, query []byte) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", f.Upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(upstreamTimeout)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// reportA extracts every A record from the upstream answer and reports it
// with the query host (trailing dot stripped).
func (f *Forwarder) reportA(host string, ans []byte) {
	if f.OnAnswer == nil {
		return
	}
	var m dnsmessage.Message
	if err := m.Unpack(ans); err != nil {
		f.logf("dnsfwd: unpack upstream answer: %v", err)
		return
	}
	host = strings.TrimSuffix(host, ".")
	for _, rr := range m.Answers {
		if a, ok := rr.Body.(*dnsmessage.AResource); ok {
			f.OnAnswer(host, a.A)
		}
	}
}
