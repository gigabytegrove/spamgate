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

// Exercise actual SMTP command/DATA framing and queue handoff with a null
// reverse path. No production MTA or mailbox is touched.
func TestSMTPNullReversePathSurvivesDurableHandoff(t *testing.T) {
	dir := t.TempDir()
	store, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sends := 0
	queue, err := NewDeliveryQueue(dir, store, func(_ context.Context, m core.Message, raw []byte) error {
		sends++
		if m.Sender != "" || len(m.Recipients) != 1 || m.Recipients[0] != "recipient@localhost" {
			t.Fatalf("null reverse path changed before relay: %+v", m)
		}
		if !strings.Contains(string(raw), "Subject: delivery report") {
			t.Fatal("durable original was changed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, trusted, _ := net.ParseCIDR("127.0.0.1/32")
	srv := &SMTP{
		Store: store, Scanner: &core.Scanner{Store: store, Resolver: smtpNullSenderResolver{}},
		CIDRs: []*net.IPNet{trusted}, Domains: []string{"localhost"}, Queue: queue,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if peer, err := listener.Accept(); err == nil {
			srv.handle(peer)
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	read := func(prefix string) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, prefix) {
			t.Fatalf("wanted %q, received %q: %v", prefix, line, err)
		}
	}
	send := func(line, prefix string) {
		t.Helper()
		if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
			t.Fatal(err)
		}
		read(prefix)
	}
	read("220 ")
	send("HELO mx.example.org", "250 ")
	send("MAIL FROM:<>", "250 ")
	send("RCPT TO:<recipient@localhost>", "250 ")
	send("DATA", "354 ")
	if _, err := fmt.Fprint(conn, "From: person@example.org\r\nTo: recipient@localhost\r\nDate: Fri, 30 Oct 2026 00:00:00 +0000\r\nMessage-ID: <dsn@localhost>\r\nSubject: delivery report\r\n\r\nAutomated report\r\n.\r\n"); err != nil {
		t.Fatal(err)
	}
	read("250 ")
	send("QUIT", "221 ")
	<-done
	snapshot, err := queue.Snapshot()
	if err != nil || snapshot.Total != 1 || snapshot.Jobs[0].Sender != "" {
		t.Fatalf("null sender not durably queued: %+v %v", snapshot, err)
	}
	if sends != 0 {
		t.Fatal("delivery occurred before worker handoff")
	}
	// RFC 7208 uses HELO as the SPF identity when MAIL FROM is null.
	// A missing HELO propagation would silently report SPF none.
	entries := store.List(10, "")
	if len(entries) != 1 || entries[0].Sender != "" {
		t.Fatalf("null sender not preserved in scan history: %+v", entries)
	}
	spfPass := false
	for _, finding := range entries[0].Findings {
		if finding.Symbol == "R_SPF_ALLOW" {
			spfPass = true
		}
	}
	if !spfPass {
		t.Fatalf("null-sender SPF did not use HELO identity: %+v", entries[0].Findings)
	}
	if err := queue.ProcessDue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sends != 1 {
		t.Fatalf("expected one downstream delivery, got %d", sends)
	}
}


type smtpNullSenderResolver struct{}

func (smtpNullSenderResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if name == "mx.example.org" {
		return []string{"v=spf1 ip4:127.0.0.1 -all"}, nil
	}
	return nil, &net.DNSError{IsNotFound: true, Name: name}
}
func (smtpNullSenderResolver) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{IsNotFound: true, Name: name}
}
func (smtpNullSenderResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	return nil, &net.DNSError{IsNotFound: true, Name: name}
}
