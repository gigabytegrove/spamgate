package core

import (
	"context"
	"testing"
)

func TestTransportScanPreservesNullReversePath(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: human@example.org\r\nTo: recipient@example.net\r\nDate: Fri, 30 Oct 2026 00:00:00 +0000\r\nMessage-ID: <dsn@example.org>\r\nSubject: Delivery Status Notification\r\n\r\nThis is an automated delivery report.\r\n")
	scanner := &Scanner{Store: store, Resolver: stubDNS{}}
	for _, connector := range []string{"smtp", "milter"} {
		t.Run(connector, func(t *testing.T) {
			m, err := scanner.Scan(context.Background(), Input{
				Raw: raw, Sender: "", Recipients: []string{"recipient@example.net"}, Connector: connector,
			})
			if err != nil {
				t.Fatal(err)
			}
			if m.Sender != "" {
				t.Fatalf("null RFC 5321 reverse path was replaced by header From: %q", m.Sender)
			}
		})
	}
	// Unconnected manual scans historically derive a display sender from From.
	m, err := scanner.Scan(context.Background(), Input{Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	if m.Sender != "human@example.org" {
		t.Fatalf("manual scan display fallback changed: %q", m.Sender)
	}
}
