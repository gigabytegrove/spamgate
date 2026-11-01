package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestSMTPDataWireFraming(t *testing.T) {
	cases := []struct {
		name, wire, want string
		max int
		wantErr error
	}{
		{"plain", "Subject: ok\r\n\r\nbody\r\n.\r\n", "Subject: ok\r\n\r\nbody\r\n", 100, nil},
		{"dot transparency", "..Subject: ok\r\n..\r\n.\r\n", ".Subject: ok\r\n.\r\n", 100, nil},
		{"literal dot prefix invalid", ".Subject: ok\r\n.\r\n", "", 100, errSMTPDataMalformed},
		{"LF-only terminator invalid", "Subject: ok\r\n.\n", "", 100, errSMTPDataMalformed},
		{"LF-only line invalid", "Subject: ok\n.\r\n", "", 100, errSMTPDataMalformed},
		{"bare CR invalid", "Subject: a\rb\r\n.\r\n", "", 100, errSMTPDataMalformed},
		{"NUL invalid", "Subject: a\x00b\r\n.\r\n", "", 100, errSMTPDataMalformed},
		{"overlong wire line", strings.Repeat("x", 999)+"\r\n.\r\n", "", 2000, errSMTPDataMalformed},
		{"998 data octets", strings.Repeat("x", 998)+"\r\n.\r\n", strings.Repeat("x", 998)+"\r\n", 2000, nil},
		{"too large", "a\r\nb\r\n.\r\n", "", 3, errSMTPDataTooLarge},
		{"unexpected EOF", "Subject: ok\r\n", "", 100, errSMTPDataMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readSMTPData(bufio.NewReader(strings.NewReader(tc.wire)), tc.max)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v, want=%v", err, tc.wantErr)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSMTPDataOversizeDrainsToNextCommand(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("a\r\nb\r\n.\r\nQUIT\r\n"))
	if _, err := readSMTPData(reader, 3); !errors.Is(err, errSMTPDataTooLarge) {
		t.Fatalf("oversize result: %v", err)
	}
	command, err := readSMTPCommand(reader)
	if err != nil || command != "QUIT" {
		t.Fatalf("DATA did not drain to terminator: command=%q err=%v", command, err)
	}
}

func TestSMTPCommandWireFraming(t *testing.T) {
	for _, tc := range []struct {
		line, want string
		bad bool
	}{
		{"EHLO example.org\r\n", "EHLO example.org", false},
		{"EHLO example.org\n", "", true},
		{"EHLO bad\rname\r\n", "", true},
		{"MAIL FROM:<a@example.org>\x00\r\n", "", true},
		{strings.Repeat("X", 510)+"\r\n", strings.Repeat("X", 510), false},
		{strings.Repeat("X", 511)+"\r\n", "", true},
	} {
		got, err := readSMTPCommand(bufio.NewReader(strings.NewReader(tc.line)))
		if (err != nil) != tc.bad || got != tc.want {
			t.Fatalf("command %q: got %q err=%v", tc.line[:min(len(tc.line), 32)], got, err)
		}
	}
}

// This loopback test deliberately has no Scanner or Queue: malformed wire
// input must never reach either subsystem or publish a durable SMTP 250.
func TestSMTPMalformedDataWireClosesBeforeScanning(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	if err := store.UpdateConfig(func(c *core.Config) error { c.SetupComplete = true; return nil }); err != nil { t.Fatal(err) }
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	_, trusted, _ := net.ParseCIDR("127.0.0.1/32")
	srv := &SMTP{Store: store, CIDRs: []*net.IPNet{trusted}, Domains: []string{"example.org"}}
	done := make(chan struct{})
	go func() { defer close(done); if peer, err := listener.Accept(); err == nil { srv.handle(peer) } }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10*time.Second))
	reader := bufio.NewReader(conn)
	read := func(want string) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, want) { t.Fatalf("want %q got %q err=%v", want, line, err) }
	}
	send := func(line, want string) {
		t.Helper()
		if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil { t.Fatal(err) }
		read(want)
	}
	read("220 ")
	send("EHLO relay.example.org", "250-")
	read("250-")
	read("250-")
	read("250 ")
	send("MAIL FROM:<sender@example.org>", "250 ")
	send("RCPT TO:<recipient@example.org>", "250 ")
	send("DATA", "354 ")
	if _, err := io.WriteString(conn, ".Subject: unstuffed\r\n.\r\nMAIL FROM:<attacker@example.org>\r\n"); err != nil { t.Fatal(err) }
	read("554 ")
	if line, err := reader.ReadString('\n'); err == nil {
		t.Fatalf("connection remained open after ambiguous DATA: %q", line)
	}
	<-done
	if got := store.List(10, ""); len(got) != 0 { t.Fatalf("malformed wire reached history: %+v", got) }
}

func TestSMTPDotTransparencyDurableOriginal(t *testing.T) {
	dir := t.TempDir()
	store, err := core.Open(dir)
	if err != nil { t.Fatal(err) }
	if err := store.UpdateConfig(func(c *core.Config) error { c.SetupComplete = true; return nil }); err != nil { t.Fatal(err) }
	var delivered []byte
	queue, err := NewDeliveryQueue(dir, store, func(_ context.Context, _ core.Message, raw []byte) error {
		delivered = append([]byte(nil), raw...)
		return nil
	})
	if err != nil { t.Fatal(err) }
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer listener.Close()
	_, trusted, _ := net.ParseCIDR("127.0.0.1/32")
	srv := &SMTP{Store: store, Scanner: &core.Scanner{Store: store, Resolver: milterStubDNS{}}, Queue: queue, CIDRs: []*net.IPNet{trusted}, Domains: []string{"localhost"}}
	done := make(chan struct{})
	go func() { defer close(done); if peer, err := listener.Accept(); err == nil { srv.handle(peer) } }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil { t.Fatal(err) }
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10*time.Second))
	reader := bufio.NewReader(conn)
	read := func(want string) {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, want) { t.Fatalf("want %q got %q err=%v", want, line, err) }
	}
	send := func(line, want string) {
		t.Helper()
		if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil { t.Fatal(err) }
		read(want)
	}
	read("220 ")
	send("HELO localhost", "250 ")
	send("MAIL FROM:<sender@localhost>", "250 ")
	send("RCPT TO:<user@localhost>", "250 ")
	send("DATA", "354 ")
	if _, err := io.WriteString(conn, "From: sender@localhost\r\nTo: user@localhost\r\nDate: Tue, 01 Jan 2030 00:00:00 +0000\r\nMessage-ID: <dot@localhost>\r\nSubject: dot transparency\r\n\r\n..leading dot\r\n.\r\n"); err != nil { t.Fatal(err) }
	read("250 ")
	send("QUIT", "221 ")
	<-done
	if err := queue.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
	if !strings.Contains(string(delivered), "\r\n.leading dot\r\n") || strings.Contains(string(delivered), "\r\n..leading dot\r\n") {
		t.Fatalf("dot transparency not preserved through durable delivery: %q", delivered)
	}
}
