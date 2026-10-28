package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/gigabytegrove/spamgate/internal/core"
	"net"
	"strings"
	"testing"
	"time"
)

func TestMilterPreservesSafeFoldedHeaders(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"smtp_crlf", "v=1; a=rsa-sha256;\r\n d=example.org; s=test"},
		{"postfix_lf", "v=1; a=rsa-sha256;\n d=example.org; s=test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := milterHeader([]byte("DKIM-Signature\x00" + tc.value + "\x00"))
			if err != nil {
				t.Fatalf("valid folded header was tempfailed: %v", err)
			}
			if !bytes.Contains(h, []byte("\r\n d=example.org")) {
				t.Fatalf("missing fold, got %q", h)
			}
			if !bytes.HasSuffix(h, []byte("\r\n")) {
				t.Fatalf("missing CRLF %q", h)
			}
		})
	}
	for _, val := range []string{
		"foo\r\nX-Injected: evil", "foo\nX-Injected: evil", "foo\rX-Injected: evil",
	} {
		if _, err := milterHeader([]byte("Subject\x00" + val + "\x00")); err == nil {
			t.Errorf("accepted header injection %q", val)
		}
	}
}

func TestMilterRealisticFoldedEmail(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error { c.SetupComplete = true; return nil }); err != nil {
		t.Fatal(err)
	}
	m := &Milter{Store: store, Scanner: &core.Scanner{Store: store, Resolver: milterStubDNS{}}}
	client, srv := net.Pipe()
	defer client.Close()
	defer srv.Close()
	done := make(chan error, 1)
	go func() { done <- m.handle(context.Background(), srv) }()
	opts := make([]byte, 12)
	binary.BigEndian.PutUint32(opts[:4], 6)
	binary.BigEndian.PutUint32(opts[4:8], milterAddHeader|milterQuarantine)
	milterSend(t, client, 'O', 'O', opts)
	milterSend(t, client, 'C', 'c', append([]byte("mx.example.org\x00\x34\x00\x19"), []byte("198.51.100.2\x00")...))
	milterSend(t, client, 'H', 'c', []byte("mx.example.org\x00"))
	milterSend(t, client, 'M', 'c', []byte("<sender@example.org>\x00"))
	milterSend(t, client, 'R', 'c', []byte("<recipient@example.net>\x00"))
	for _, v := range []string{
		"From\x00sender@example.org\x00",
		"Subject\x00Normal email\x00",
		"Date\x00Tue, 27 Oct 2026 13:00:00 -0400\x00",
		"Message-ID\x00<realistic@example.org>\x00",
		"X-Long\x00hello;\r\n world\x00",
	} {
		milterSend(t, client, 'L', 'c', []byte(v))
	}
	milterSend(t, client, 'N', 'c', nil)
	milterSend(t, client, 'B', 'c', []byte("A legitimate email\r\n"))
	milterSend(t, client, 'E', 'c', nil)
	msgs := store.List(10, "")
	if len(msgs) != 1 {
		t.Fatalf("expected message recorded after folded headers, got %d", len(msgs))
	}
	if strings.TrimSpace(msgs[0].Subject) != "Normal email" {
		t.Fatal("subject corrupted")
	}
	hdr, err := store.Headers(msgs[0].ID)
	if err != nil || !strings.Contains(hdr.Raw, "X-Long: hello;\r\n world") || strings.Contains(hdr.Raw, "A legitimate email") {
		t.Fatalf("Milter must persist folded headers only, not body: %+v, %v", hdr, err)
	}
	milterSend(t, client, 'Q', 0, nil)
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("milter stalled")
	}
}
