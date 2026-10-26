package transport

import (
	"bufio"
	"context"
	"fmt"
	"github.com/gigabytegrove/spamgate/internal/core"
	"net"
	"strings"
	"testing"
	"time"
)

// End-to-end RFC 5321-style envelope/DATA reception through the real TCP
// SMTP handler, durable acknowledgement, then delivery worker recovery.
func TestSMTPDurableOutboxAcknowledgment(t *testing.T) {
	dir := t.TempDir()
	store, err := core.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error { c.SetupComplete = true; return nil }); err != nil {
		t.Fatal(err)
	}
	sent := 0
	queue, err := NewDeliveryQueue(dir, store, func(_ context.Context, m core.Message, raw []byte) error {
		sent++
		if m.Sender != "sender@localhost" || !strings.Contains(string(raw), "Subject: accepted") {
			t.Fatalf("SMTP envelope corrupted: %+v", m)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, peer, _ := net.ParseCIDR("127.0.0.1/32")
	srv := &SMTP{Store: store, Scanner: &core.Scanner{Store: store}, CIDRs: []*net.IPNet{peer}, Domains: []string{"localhost"}, Queue: queue}
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e == nil {
			srv.handle(c)
		}
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	read := func(code string) {
		t.Helper()
		v, e := r.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		if !strings.HasPrefix(v, code) {
			t.Fatalf("wanted %s, got %q", code, v)
		}
	}
	cmd := func(line, code string) {
		t.Helper()
		if _, e := fmt.Fprintf(c, "%s\r\n", line); e != nil {
			t.Fatal(e)
		}
		read(code)
	}
	read("220 ")
	cmd("HELO localhost", "250 ")
	cmd("MAIL FROM:<sender@localhost>", "250 ")
	cmd("RCPT TO:<user@localhost>", "250 ")
	cmd("DATA", "354 ")
	if _, e := fmt.Fprint(c, "From: sender@localhost\r\nTo: user@localhost\r\nDate: Tue, 01 Jan 2030 00:00:00 +0000\r\nMessage-ID: <smtp@localhost>\r\nSubject: accepted\r\n\r\nHello\r\n.\r\n"); e != nil {
		t.Fatal(e)
	}
	read("250 ")
	cmd("QUIT", "221 ")
	<-done
	if sent != 0 {
		t.Fatal("relay sent before durable acknowledgment")
	}
	snapshot, e := queue.Snapshot()
	if e != nil || snapshot.Total != 1 {
		t.Fatalf("missing durable envelope %+v %v", snapshot, e)
	}
	if e := queue.ProcessDue(context.Background()); e != nil {
		t.Fatal(e)
	}
	if sent != 1 {
		t.Fatal("worker failed to forward")
	}
	snapshot, _ = queue.Snapshot()
	if snapshot.Total != 0 {
		t.Fatal("delivered envelope not removed")
	}
}
