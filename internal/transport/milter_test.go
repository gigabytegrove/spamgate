package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func milterRead(t *testing.T, conn net.Conn, expect byte) []byte {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	cmd, payload, err := readMilterFrame(conn)
	if err != nil {
		t.Fatalf("read %c: %v", expect, err)
	}
	if cmd != expect {
		t.Fatalf("expected %c got %c: %q", expect, cmd, payload)
	}
	return payload
}
func milterSend(t *testing.T, c net.Conn, cmd, expect byte, data []byte) []byte {
	t.Helper()
	if err := writeMilterFrame(c, cmd, data); err != nil {
		t.Fatal(err)
	}
	if expect == 0 {
		return nil
	}
	return milterRead(t, c, expect)
}

type milterStubDNS struct{}

func (milterStubDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if strings.HasPrefix(name, "_dmarc.") {
		return []string{"v=DMARC1; p=none"}, nil
	}
	return nil, &net.DNSError{IsNotFound: true, Name: name}
}
func (milterStubDNS) LookupIPAddr(_ context.Context, n string) ([]net.IPAddr, error) {
	return nil, &net.DNSError{IsNotFound: true, Name: n}
}
func (milterStubDNS) LookupMX(_ context.Context, n string) ([]*net.MX, error) {
	return nil, &net.DNSError{IsNotFound: true, Name: n}
}
func TestMilterTransactionAndReuse(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error { c.SetupComplete = true; return nil }); err != nil {
		t.Fatal(err)
	}
	m := &Milter{Store: store, Scanner: &core.Scanner{Store: store, Resolver: milterStubDNS{}}}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- m.handle(context.Background(), server) }()
	opts := make([]byte, 12)
	binary.BigEndian.PutUint32(opts[:4], 6)
	binary.BigEndian.PutUint32(opts[4:8], milterAddHeader|milterQuarantine)
	negotiated := milterSend(t, client, 'O', 'O', opts)
	if binary.BigEndian.Uint32(negotiated[:4]) != 6 {
		t.Fatalf("bad negotiation %x", negotiated)
	}
	if binary.BigEndian.Uint32(negotiated[4:8]) != milterAddHeader|milterQuarantine {
		t.Fatalf("bad options %x", negotiated)
	}
	milterSend(t, client, 'C', 'c', append([]byte("gateway\x00\x34\x00\x19"), []byte("198.51.100.5\x00")...))
	milterSend(t, client, 'M', 'c', []byte("<sender@example.org>\x00"))
	milterSend(t, client, 'R', 'c', []byte("<recipient@example.org>\x00"))
	for _, line := range [][2]string{{"From", "sender@example.org"}, {"Subject", "hello"}, {"Date", "Mon, 26 Oct 2026 14:00:00 +0000"}, {"Message-ID", "<test1@example.org>"}} {
		milterSend(t, client, 'L', 'c', append(append([]byte(line[0]), 0), append([]byte(line[1]), 0)...))
	}
	milterSend(t, client, 'N', 'c', nil)
	milterSend(t, client, 'B', 'c', []byte("Regular body\r\n"))
	milterSend(t, client, 'E', 'c', nil)
	if msgs := store.List(10, ""); len(msgs) != 1 || msgs[0].Connector != "milter" {
		t.Fatalf("expected one milter event; got %+v", msgs)
	}
	// The same connection may process another message without re-negotiation.
	milterSend(t, client, 'M', 'c', []byte("<sender@example.org>\x00"))
	milterSend(t, client, 'R', 'c', []byte("<recipient@example.org>\x00"))
	milterSend(t, client, 'L', 'c', []byte("From\x00sender@example.org\x00"))
	milterSend(t, client, 'L', 'c', []byte("Subject\x00verify your account\x00"))
	milterSend(t, client, 'N', 'c', nil)
	milterSend(t, client, 'B', 'c', []byte("confirm your password\r\n"))
	milterSend(t, client, 'E', 'h', nil)
	for _, name := range []string{"X-Spam-Status", "X-SpamGate-Score", "X-SpamGate-Action", "X-SpamGate-ID"} {
		data := milterRead(t, client, 'h')
		if !bytes.HasPrefix(data, []byte(name+"\x00")) {
			t.Fatalf("expected %s header, got %q", name, data)
		}
	}
	milterRead(t, client, 'c')
	if msgs := store.List(10, ""); len(msgs) != 2 {
		t.Fatalf("expected two events, got %d", len(msgs))
	} else if msgs[0].MTAAction != "spam_header_requested" || msgs[0].Delivery != "" {
		t.Fatalf("expected unconfirmed tag request, got %+v", msgs[0])
	} else if msgs[1].MTAAction != "continue_requested" || msgs[1].Delivery != "" {
		t.Fatalf("expected unconfirmed MTA continue request, got %+v", msgs[1])
	}
	milterSend(t, client, 'Q', 0, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("milter did not exit")
	}
}
func TestMilterFramingAndHeaders(t *testing.T) {
	for _, b := range [][]byte{{0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}} {
		if _, _, err := readMilterFrame(bytes.NewReader(b)); err == nil {
			t.Fatal("accepted invalid frame")
		}
	}
	if _, err := milterHeader([]byte("X\x00hello\r\nInjected: value\x00")); err == nil {
		t.Fatal("injection accepted")
	}
	buf := new(bytes.Buffer)
	if err := writeMilterFrame(buf, 'x', []byte("abc")); err != nil {
		t.Fatal(err)
	}
	cmd, payload, err := readMilterFrame(buf)
	if err != nil || cmd != 'x' || string(payload) != "abc" {
		t.Fatalf("bad roundtrip %c %s %v", cmd, payload, err)
	}
	if _, _, err := readMilterFrame(bytes.NewReader([]byte{0, 0, 0, 5, 'X'})); err != io.ErrUnexpectedEOF {
		t.Fatalf("expected partial-frame EOF, got %v", err)
	}
}
