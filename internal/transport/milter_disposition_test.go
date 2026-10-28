package transport

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestMilterQuarantineRecordsRequestNotMailboxDelivery(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Rules = append(c.Rules, core.Rule{
			ID: "forced_hold_test", Name: "Force hold", Kind: "sender_email",
			Value: "sender@example.org", Action: "quarantine", Enabled: true,
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	filter := &Milter{Store: store, Scanner: &core.Scanner{Store: store, Resolver: milterStubDNS{}}}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- filter.handle(context.Background(), server) }()
	opts := make([]byte, 12)
	binary.BigEndian.PutUint32(opts[:4], 6)
	binary.BigEndian.PutUint32(opts[4:8], milterAddHeader|milterQuarantine)
	milterSend(t, client, 'O', 'O', opts)
	milterSend(t, client, 'M', 'c', []byte("<sender@example.org>\x00"))
	milterSend(t, client, 'R', 'c', []byte("<recipient@example.net>\x00"))
	if err := writeMilterFrame(client, 'D', []byte("Ei\x00AB12CD34\x00")); err != nil {
		t.Fatal(err)
	}
	milterSend(t, client, 'L', 'c', []byte("From\x00sender@example.org\x00"))
	milterSend(t, client, 'L', 'c', []byte("Subject\x00Quarantine test\x00"))
	milterSend(t, client, 'N', 'c', nil)
	milterSend(t, client, 'B', 'c', []byte("Hello\r\n"))
	milterSend(t, client, 'E', 'q', nil) // Postfix quarantine request
	milterRead(t, client, 'c')           // Continue after Milter action callback
	got := store.List(10, "")
	if len(got) != 1 {
		t.Fatalf("expected one scan, got %d", len(got))
	}
	if got[0].Action != "quarantine" || got[0].MTAAction != "postfix_hold_requested" || got[0].Delivery != "" || got[0].MTAQueueID != "AB12CD34" {
		t.Fatalf("must distinguish quarantine request from confirmed delivery/hold: %+v", got[0])
	}
	milterSend(t, client, 'Q', 0, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not terminate")
	}
}
