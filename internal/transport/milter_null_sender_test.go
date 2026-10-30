package transport

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// Queue-ID correlation must not depend on a nonempty MAIL FROM: null
// reverse paths are legitimate DSNs and still have Postfix queue IDs.
func TestMilterNullReversePathQueueIDCorrelation(t *testing.T) {
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
	// A macro before MAIL FROM is not evidence for the current transaction.
	milterSend(t, client, 'D', 0, []byte("Ei\x00STALE123\x00"))
	milterSend(t, client, 'M', 'c', []byte("<>\x00"))
	milterSend(t, client, 'D', 0, []byte("Ei\x00NULLDSN123\x00"))
	milterSend(t, client, 'R', 'c', []byte("<recipient@example.org>\x00"))
	for _, h := range [][2]string{
		{"From", "human@example.org"},
		{"Date", "Fri, 30 Oct 2026 00:00:00 +0000"},
		{"Message-ID", "<dsn@example.org>"},
		{"Subject", "Delivery report"},
	} {
		milterSend(t, client, 'L', 'c', append(append([]byte(h[0]), 0), append([]byte(h[1]), 0)...))
	}
	milterSend(t, client, 'N', 'c', nil)
	milterSend(t, client, 'B', 'c', []byte("Normal status report\r\n"))
	milterSend(t, client, 'E', 'c', nil)
	messages := store.List(10, "")
	if len(messages) != 1 {
		t.Fatalf("expected one scan, got %+v", messages)
	}
	if messages[0].Sender != "" || messages[0].MTAQueueID != "NULLDSN123" {
		t.Fatalf("lost null envelope or correlated stale queue ID: %+v", messages[0])
	}
	milterSend(t, client, 'Q', 0, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("milter handler did not exit")
	}
}
