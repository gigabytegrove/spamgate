package transport

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// Postfix is allowed to split original ADDR and HELO across XFORWARD
// commands. An ADDR-only command must not erase the SMTP greeting for null
// sender SPF; a HELO-only command must still override the relay greeting.
func TestSMTPXForwardPartialIdentityPreservesNullSenderSPF(t *testing.T) {
	for _, tc := range []struct{
		name, greeting, xforward string
	}{
		{"address_only", "mx.example.org", "ADDR=127.0.0.1"},
		{"helo_only", "relay.internal", "HELO=mx.example.org"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			store, err := core.Open(dir)
			if err != nil { t.Fatal(err) }
			if err := store.UpdateConfig(func(c *core.Config) error {
				c.SetupComplete = true
				return nil
			}); err != nil { t.Fatal(err) }
			queue, err := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error { return nil })
			if err != nil { t.Fatal(err) }
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil { t.Fatal(err) }
			defer listener.Close()
			_, trusted, _ := net.ParseCIDR("127.0.0.1/32")
			srv := &SMTP{Store: store, Scanner: &core.Scanner{Store: store, Resolver: smtpNullSenderResolver{}},
				CIDRs: []*net.IPNet{trusted}, Domains: []string{"localhost"}, Queue: queue}
			done := make(chan struct{})
			go func() {
				defer close(done)
				if peer, err := listener.Accept(); err == nil { srv.handle(peer) }
			}()
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil { t.Fatal(err) }
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10*time.Second))
			reader := bufio.NewReader(conn)
			read := func(prefix string) {
				t.Helper()
				line, err := reader.ReadString('\n')
				if err != nil || !strings.HasPrefix(line, prefix) {
					t.Fatalf("expected %q, got %q: %v", prefix, line, err)
				}
			}
			send := func(line, prefix string) {
				t.Helper()
				if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil { t.Fatal(err) }
				read(prefix)
			}
			read("220 ")
			send("HELO "+tc.greeting, "250 ")
			send("XFORWARD "+tc.xforward, "250 ")
			send("MAIL FROM:<>", "250 ")
			send("RCPT TO:<recipient@localhost>", "250 ")
			send("DATA", "354 ")
			if _, err := fmt.Fprint(conn, "From: sender@example.org\r\nTo: recipient@localhost\r\nDate: Fri, 30 Oct 2026 00:00:00 +0000\r\nMessage-ID: <partial@localhost>\r\nSubject: partial XFORWARD identity\r\n\r\nNormal delivery status notification\r\n.\r\n"); err != nil { t.Fatal(err) }
			read("250 ")
			send("QUIT", "221 ")
			<-done
			scans := store.List(10, "")
			if len(scans) != 1 || scans[0].Sender != "" {
				t.Fatalf("missing null-sender scan: %+v", scans)
			}
			pass := false
			for _, finding := range scans[0].Findings {
				if finding.Symbol == "R_SPF_ALLOW" { pass = true }
			}
			if !pass {
				t.Fatalf("SPF did not use original HELO with %q: %+v", tc.xforward, scans[0].Findings)
			}
			snapshot, err := queue.Snapshot()
			if err != nil || snapshot.Total != 1 { t.Fatalf("mail not durably queued: %+v %v", snapshot, err) }
		})
	}
}

func TestSMTPXForwardRejectsDuplicateIdentityAcrossCommands(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	_, trusted, _ := net.ParseCIDR("127.0.0.1/32")
	srv := &SMTP{Store: store, CIDRs: []*net.IPNet{trusted}, Domains: []string{"localhost"}}
	done := make(chan struct{})
	go func() { defer close(done); if peer, err := listener.Accept(); err == nil { srv.handle(peer) } }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10*time.Second))
	reader := bufio.NewReader(conn)
	read := func(code string) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, code) { t.Fatalf("expected %q, got %q: %v", code, line, err) }
	}
	send := func(line, code string) {
		t.Helper()
		if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil { t.Fatal(err) }
		read(code)
	}
	read("220 ")
	send("HELO relay.internal", "250 ")
	send("XFORWARD ADDR=198.51.100.10", "250 ")
	send("XFORWARD ADDR=203.0.113.12", "501 ")
	send("XFORWARD HELO=mx.example.org", "250 ")
	send("XFORWARD HELO=evil.example.org", "501 ")
	send("RSET", "250 ")
	send("XFORWARD ADDR=203.0.113.12 HELO=mx.example.org", "250 ")
	send("QUIT", "221 ")
	<-done
}
