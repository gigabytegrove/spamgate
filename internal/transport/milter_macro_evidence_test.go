package transport

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestMilterQueueIDEvidenceDistinguishesAbsenceFromCorruption(t *testing.T) {
	cases := []struct {
		name string
		data string
		id string
		claimed bool
		invalid bool
	}{
		{"normal", "E{i}\x00AB12CD34\x00", "AB12CD34", true, false},
		{"empty-before-assignment", "E{i}\x00\x00", "", true, false},
		{"unrelated", "E{if_addr}\x00192.0.2.1\x00", "", false, false},
		{"no-definitions", "E", "", false, false},
		{"unterminated", "Ei\x00AB12CD34", "", false, true},
		{"odd-pairs", "Ei\x00AB12CD34\x00j\x00", "", false, true},
		{"duplicate", "Ei\x00AB12CD34\x00{i}\x00AB12CD34\x00", "", true, true},
		{"invalid-id", "Ei\x00AB-12\x00", "", true, true},
		{"oversized", "Ei\x00ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567\x00", "", true, true},
		{"double-braces", "E{{i}}\x00AB12CD34\x00", "", true, true},
		{"missing-open-brace", "Ei}\x00AB12CD34\x00", "", true, true},
		{"missing-close-brace", "E{i\x00AB12CD34\x00", "", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, claimed, err := milterQueueIDEvidence([]byte(tc.data))
			if (err != nil) != tc.invalid || id != tc.id || claimed != tc.claimed {
				t.Fatalf("id=%q claimed=%v err=%v; expected id=%q claimed=%v invalid=%v", id, claimed, err, tc.id, tc.claimed, tc.invalid)
			}
		})
	}
}

func TestMilterMalformedQueueIdentityCannotReuseEarlierID(t *testing.T) {
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
	options := make([]byte, 12)
	binary.BigEndian.PutUint32(options[:4], 6)
	binary.BigEndian.PutUint32(options[4:8], milterAddHeader|milterQuarantine)
	milterSend(t, client, 'O', 'O', options)

	start := func() {
		t.Helper()
		milterSend(t, client, 'M', 'c', []byte("<sender@example.org>\x00"))
		milterSend(t, client, 'R', 'c', []byte("<recipient@example.net>\x00"))
		milterSend(t, client, 'L', 'c', []byte("From\x00sender@example.org\x00"))
		milterSend(t, client, 'L', 'c', []byte("Subject\x00Routine report\x00"))
		milterSend(t, client, 'N', 'c', nil)
		milterSend(t, client, 'B', 'c', []byte("Routine report\r\n"))
	}
	macro := func(data string) {
		t.Helper()
		if err := writeMilterFrame(client, 'D', []byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{
		"Ei\x00BAD-QUEUE\x00",
		"Ei\x00AB12CD34\x00{i}\x00AB12CD34\x00",
		"E{{i}}\x00AB12CD34\x00",
		"Ei\x00AB12CD34",
		"Ei\x00AB12CD34\x00j\x00",
	} {
		start()
		macro("Ei\x00AB12CD34\x00")
		macro(bad)
		milterSend(t, client, 'E', 't', nil)
		if got := store.List(10, ""); len(got) != 0 {
			t.Fatalf("malformed queue evidence recorded a misleading scan: %+v", got)
		}
	}
	start()
	macro("E{i}\x00\x00") // Postfix may not have allocated a queue ID yet.
	macro("E{if_addr}\x00192.0.2.1\x00")
	macro("Ei\x00GOOD1234\x00")
	milterSend(t, client, 'E', 'c', nil)
	got := store.List(10, "")
	if len(got) != 1 || got[0].MTAQueueID != "GOOD1234" {
		t.Fatalf("valid later transaction lost queue identity: %+v", got)
	}
	milterSend(t, client, 'Q', 0, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5*time.Second):
		t.Fatal("milter handler did not exit")
	}
}
