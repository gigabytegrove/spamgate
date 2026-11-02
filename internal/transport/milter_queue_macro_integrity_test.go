package transport

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// Conflicting Postfix macro evidence must never be attached to a different
// held message, nor should the failure poison a later SMTP transaction.
func TestMilterConflictingQueueIDMacrosTempfailAndRecover(t *testing.T) {
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

	start := func() {
		t.Helper()
		milterSend(t, client, 'M', 'c', []byte("<sender@example.org>\x00"))
		milterSend(t, client, 'R', 'c', []byte("<recipient@example.net>\x00"))
		milterSend(t, client, 'L', 'c', []byte("From\x00sender@example.org\x00"))
		milterSend(t, client, 'L', 'c', []byte("Subject\x00Routine update\x00"))
		milterSend(t, client, 'N', 'c', nil)
		milterSend(t, client, 'B', 'c', []byte("Routine status report\r\n"))
	}
	macro := func(id string) {
		t.Helper()
		if err := writeMilterFrame(client, 'D', []byte("Ei\x00"+id+"\x00")); err != nil {
			t.Fatal(err)
		}
	}
	start()
	macro("AB12CD34")
	macro("ZZ99YY88")
	milterSend(t, client, 'E', 't', nil)
	if got := store.List(10, ""); len(got) != 0 {
		t.Fatalf("conflicting queue IDs produced persisted verdict: %d", len(got))
	}

	start()
	macro("EF56GH78")
	macro("EF56GH78") // repeated identical evidence is not a conflict
	milterSend(t, client, 'E', 'c', nil)
	got := store.List(10, "")
	if len(got) != 1 || got[0].MTAQueueID != "EF56GH78" {
		t.Fatalf("valid transaction lost its queue identity: %+v", got)
	}

	start()
	milterSend(t, client, 'E', 'c', nil)
	got = store.List(10, "")
	if len(got) != 2 || got[0].MTAQueueID != "" {
		t.Fatalf("previous transaction's queue ID leaked into next message: %+v", got)
	}

	milterSend(t, client, 'Q', 0, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("milter did not terminate")
	}
}

func TestMilterQueueIDMacroNameDoesNotAcceptExtraBraces(t *testing.T) {
	for _, tc := range []struct {
		name, packet, want string
	}{
		{"plain", "Ei\x00AB12CD34\x00", "AB12CD34"},
		{"braced", "E{i}\x00AB12CD34\x00", "AB12CD34"},
		{"double braces", "E{{i}}\x00AB12CD34\x00", ""},
		{"open brace", "E{i\x00AB12CD34\x00", ""},
		{"closing brace", "Ei}\x00AB12CD34\x00", ""},
		{"duplicate aliases", "Ei\x00AB12CD34\x00{i}\x00AB12CD34\x00", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := milterQueueID([]byte(tc.packet)); got != tc.want {
				t.Fatalf("queue ID %q, want %q", got, tc.want)
			}
		})
	}
}
