package transport

import (
	"bufio"
	"fmt"
	"github.com/gigabytegrove/spamgate/internal/core"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSMTPQuarantineAndXForward(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Rules = append(c.Rules, core.Rule{ID: "hold", Name: "Block test sender", Kind: "sender_email", Value: "spam@example.net", Action: "quarantine", Score: 14, Enabled: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, trusted, _ := net.ParseCIDR("127.0.0.1/32")
	smtp := &SMTP{Store: store, Scanner: &core.Scanner{Store: store, Resolver: milterStubDNS{}}, CIDRs: []*net.IPNet{trusted}, Domains: []string{"example.org"}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		peer, e := listener.Accept()
		if e == nil {
			smtp.handle(peer)
		}
	}()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	read := func(expect string) {
		t.Helper()
		line, e := reader.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if !strings.HasPrefix(line, expect) {
			t.Fatalf("wanted prefix %s, got %q", expect, line)
		}
	}
	send := func(line, expect string) {
		t.Helper()
		if _, e := fmt.Fprintf(conn, "%s\r\n", line); e != nil {
			t.Fatal(e)
		}
		read(expect)
	}
	read("220 ")
	send("HELO test.example.net", "250 ")
	send("RCPT TO:<alice@example.org>", "503 ")
	send("XFORWARD addr=203.0.113.8", "250 ")
	send("MAIL FROM:<spam@example.net>", "250 ")
	send("RCPT TO:<alice@example.org>", "250 ")
	send("DATA", "354 ")
	_, err = fmt.Fprint(conn, "From: spam@example.net\r\nTo: alice@example.org\r\nSubject: visible\r\n\r\nhello\r\n.\r\n")
	if err != nil {
		t.Fatal(err)
	}
	read("250 ")
	send("QUIT", "221 ")
	<-done
	entries := store.List(10, "")
	if len(entries) != 1 {
		t.Fatalf("unexpected message count %d", len(entries))
	}
	m := entries[0]
	if m.ClientIP != "203.0.113.8" || m.IngestIP != "127.0.0.1" || m.Delivery != "quarantined" || m.Action != "quarantine" {
		t.Fatalf("unexpected SMTP verdict %+v", m)
	}
	raw, err := store.Quarantined(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "Subject: visible") {
		t.Fatalf("held original missing subject")
	}
}
