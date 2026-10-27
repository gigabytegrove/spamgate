package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// Regression: long, folded RFC 5322 headers are normal for mail from Gmail.
func TestMilterFoldedHeaderCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, value string
	}{
		{"rfc_crlf", "v=1; a=rsa-sha256;\r\n d=example.org; s=selector"},
		{"postfix_lf", "v=1; a=rsa-sha256;\n d=example.org; s=selector"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := milterHeader([]byte("DKIM-Signature\x00" + tc.value + "\x00"))
			if err != nil {
				t.Fatalf("valid folded header rejected: %v", err)
			}
			if !bytes.Contains(got, []byte("\r\n d=example.org")) {
				t.Fatalf("folding lost: %q", got)
			}
		})
	}
	for _, invalid := range []string{
		"subject\r\nX-Injected: value", "subject\nX-Injected: value", "subject\rX-Injected: value",
	} {
		if _, err := milterHeader([]byte("Subject\x00" + invalid + "\x00")); err == nil {
			t.Errorf("accepted header injection %q", invalid)
		}
	}
}

func TestMilterAcceptsFoldedHeaderMessage(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		return nil
	}); err != nil {
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
	milterSend(t, client, 'O', 'O', opts)
	milterSend(t, client, 'M', 'c', []byte("<sender@example.org>\x00"))
	milterSend(t, client, 'R', 'c', []byte("<recipient@example.net>\x00"))
	for _, header := range []string{
		"From\x00sender@example.org\x00",
		"Subject\x00Legitimate email\x00",
		"Date\x00Tue, 27 Oct 2026 13:00:00 -0400\x00",
		"Message-ID\x00<folded@example.org>\x00",
		"X-Example\x00value;\r\n continuation\x00",
	} {
		milterSend(t, client, 'L', 'c', []byte(header))
	}
	milterSend(t, client, 'N', 'c', nil)
	milterSend(t, client, 'B', 'c', []byte("Hello\r\n"))
	milterSend(t, client, 'E', 'c', nil)
	messages := store.List(10, "")
	if len(messages) != 1 || !strings.EqualFold(messages[0].Connector, "milter") {
		t.Fatalf("message was not scanned and recorded: %+v", messages)
	}
	milterSend(t, client, 'Q', 0, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Milter did not exit")
	}
}
