package transport

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestMilterEnvelopeCallbackStrictWire(t *testing.T) {
	cases := []struct {
		name string
		wire string
		null bool
		want string
		ok bool
	}{
		{"mail", "<sender@example.org>\x00", true, "sender@example.org", true},
		{"recipient", "<user@example.net>\x00", false, "user@example.net", true},
		{"esmtp mail", "<sender@example.org>\x00BODY=8BITMIME\x00SIZE=123\x00", true, "sender@example.org", true},
		{"esmtp rcpt", "<user@example.net>\x00NOTIFY=SUCCESS,FAILURE\x00", false, "user@example.net", true},
		{"null reverse path", "<>\x00", true, "", true},
		{"null recipient", "<>\x00", false, "", false},
		{"bare empty sender", "\x00", true, "", false},
		{"unterminated", "<sender@example.org>", true, "", false},
		{"trailing junk", "<sender@example.org>\x00junk", true, "", false},
		{"second empty argument", "<sender@example.org>\x00\x00", true, "", false},
		{"injected CRLF", "<sender@example.org>\r\nRCPT TO:<victim@example.org>\x00", true, "", false},
		{"leading space", " <sender@example.org>\x00", true, "", false},
		{"unbalanced path", "<sender@example.org\x00", true, "", false},
		{"invalid utf8", "<sender@\xff.example>\x00", true, "", false},
		{"invalid esmtp argument", "<sender@example.org>\x00BODY=8BITMIME\r\nINJECTED\x00", true, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := milterEnvelopeAddress([]byte(tc.wire), tc.null)
			if (err == nil) != tc.ok || (tc.ok && got != tc.want) {
				t.Fatalf("got %q, err %v; want %q valid=%t", got, err, tc.want, tc.ok)
			}
		})
	}
}

func TestMilterClientIPFamilyCannotBeSwapped(t *testing.T) {
	for _, wire := range []string{
		"mx.example\x004\x00\x19" + "2001:db8::1\x00",
		"mx.example\x006\x00\x19" + "198.51.100.2\x00",
	} {
		if got := milterAddress([]byte(wire)); got != "" {
			t.Fatalf("accepted wrong address family: %q", got)
		}
	}
}

func TestMilterEnvelopeFailureCannotBeResetBySecondMail(t *testing.T) {
	cases := []struct {
		name string
		fail func(*testing.T, net.Conn)
	}{
		{"malformed mail", func(t *testing.T, c net.Conn) {
			milterSend(t, c, 'M', 't', []byte("<sender@example.org>\x00ignored"))
		}},
		{"malformed recipient", func(t *testing.T, c net.Conn) {
			milterSend(t, c, 'M', 'c', []byte("<sender@example.org>\x00"))
			milterSend(t, c, 'R', 't', []byte("<recipient@example.net>\x00injected"))
		}},
		{"duplicate mail", func(t *testing.T, c net.Conn) {
			milterSend(t, c, 'M', 'c', []byte("<sender@example.org>\x00"))
			milterSend(t, c, 'M', 't', []byte("<other@example.org>\x00"))
		}},
		{"client identity mutation", func(t *testing.T, c net.Conn) {
			milterSend(t, c, 'M', 'c', []byte("<sender@example.org>\x00"))
			milterSend(t, c, 'C', 't', []byte("mx.example\x004\x00\x19" + "198.51.100.4\x00"))
		}},
		{"helo mutation", func(t *testing.T, c net.Conn) {
			milterSend(t, c, 'M', 'c', []byte("<sender@example.org>\x00"))
			milterSend(t, c, 'H', 't', []byte("spoof.example\x00"))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, err := core.Open(t.TempDir())
			if err != nil { t.Fatal(err) }
			if err := store.UpdateConfig(func(c *core.Config) error {
				c.SetupComplete = true
				return nil
			}); err != nil { t.Fatal(err) }
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
			tc.fail(t, client)
			// An attempted second MAIL cannot silently reset the failure.
			milterSend(t, client, 'M', 't', []byte("<replacement@example.org>\x00"))
			milterSend(t, client, 'E', 't', nil)
			if got := store.List(10, ""); len(got) != 0 {
				t.Fatalf("failed transaction persisted: %+v", got)
			}
			// Fresh EOM boundary permits a new valid transaction.
			milterSend(t, client, 'M', 'c', []byte("<sender@example.org>\x00BODY=8BITMIME\x00"))
			milterSend(t, client, 'R', 'c', []byte("<recipient@example.net>\x00NOTIFY=FAILURE\x00"))
			milterSend(t, client, 'L', 'c', []byte("From\x00sender@example.org\x00"))
			milterSend(t, client, 'N', 'c', nil)
			milterSend(t, client, 'B', 'c', []byte("Routine status report\r\n"))
			milterSend(t, client, 'E', 'c', nil)
			if got := store.List(10, ""); len(got) != 1 || got[0].Sender != "sender@example.org" {
				t.Fatalf("valid recovery lost: %+v", got)
			}
			milterSend(t, client, 'Q', 0, nil)
			select {
			case err := <-done:
				if err != nil { t.Fatal(err) }
			case <-time.After(5*time.Second):
				t.Fatal("milter did not terminate")
			}
		})
	}
}
