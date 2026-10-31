package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

type fragmentedMilterWriter struct {
	bytes.Buffer
	max int
}

func (w *fragmentedMilterWriter) Write(p []byte) (int, error) {
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.Buffer.Write(p)
}

type stalledMilterWriter struct{}

func (stalledMilterWriter) Write([]byte) (int, error) { return 0, nil }

type failingMilterWriter struct{ err error }

func (w failingMilterWriter) Write([]byte) (int, error) { return 0, w.err }

func TestMilterFrameWriterHandlesFragmentedWrites(t *testing.T) {
	for _, max := range []int{1, 2, 3, 7} {
		t.Run(strings.Repeat("x", max), func(t *testing.T) {
			writer := &fragmentedMilterWriter{max: max}
			payload := []byte("authenticated milter response")
			if err := writeMilterFrame(writer, 'h', payload); err != nil {
				t.Fatal(err)
			}
			cmd, got, err := readMilterFrame(&writer.Buffer)
			if err != nil || cmd != 'h' || !bytes.Equal(got, payload) {
				t.Fatalf("truncated frame: command=%q payload=%q error=%v", cmd, got, err)
			}
			if writer.Len() != 0 {
				t.Fatalf("trailing frame bytes: %d", writer.Len())
			}
		})
	}
}

func TestMilterFrameWriterRejectsStallAndErrors(t *testing.T) {
	if err := writeMilterFrame(stalledMilterWriter{}, 'c', nil); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("stalled writer: %v", err)
	}
	sentinel := errors.New("connection lost")
	if err := writeMilterFrame(failingMilterWriter{sentinel}, 'c', nil); !errors.Is(err, sentinel) {
		t.Fatalf("writer error lost: %v", err)
	}
	if err := writeMilterFrame(&bytes.Buffer{}, 'c', make([]byte, milterMaxFrame)); err == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestMilterQueueIDRequiresCompleteUnambiguousMacros(t *testing.T) {
	for _, tc := range []struct {
		name string
		packet string
		want string
	}{
		{"plain", "Ei\x00AB12CD34\x00", "AB12CD34"},
		{"braced", "E{i}\x00AB12CD34\x00", "AB12CD34"},
		{"other macro", "Ej\x00mailhost\x00i\x00AB12CD34\x00", "AB12CD34"},
		{"missing terminator", "Ei\x00AB12CD34", ""},
		{"odd name value pairs", "Ei\x00AB12CD34\x00j\x00", ""},
		{"duplicate ID", "Ei\x00AB12CD34\x00i\x00BAD567\x00", ""},
		{"empty ID", "Ei\x00\x00", ""},
		{"invalid character", "Ei\x00AB-12\x00", ""},
		{"oversized ID", "Ei\x00" + strings.Repeat("A", 33) + "\x00", ""},
		{"no queue macro", "Ej\x00mailhost\x00", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := milterQueueID([]byte(tc.packet)); got != tc.want {
				t.Fatalf("queue ID %q, expected %q", got, tc.want)
			}
		})
	}
}

func TestMilterHeaderRejectsTrailingCallbackData(t *testing.T) {
	for _, packet := range [][]byte{
		[]byte("Subject\x00safe\x00ignored"),
		[]byte("Subject\x00safe\x00extra\x00"),
		[]byte("Subject\x00safe"),
	} {
		if _, err := milterHeader(packet); err == nil {
			t.Fatalf("accepted malformed header callback %q", packet)
		}
	}
	if got, err := milterHeader([]byte("Subject\x00safe\x00")); err != nil || string(got) != "Subject: safe\r\n" {
		t.Fatalf("valid header rejected: %q, %v", got, err)
	}
}

func TestMilterMalformedHeaderTempfailsWithoutSavingAndRecovers(t *testing.T) {
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
	milterSend(t, client, 'M', 'c', []byte("<sender@example.org>\\x00"))
	milterSend(t, client, 'R', 'c', []byte("<recipient@example.org>\\x00"))
	milterSend(t, client, 'L', 't', []byte("Subject\\x00safe\\x00Injected: bad"))
	milterSend(t, client, 'E', 't', nil)
	if messages := store.List(10, ""); len(messages) != 0 {
		t.Fatalf("invalid transaction saved a verdict: %d", len(messages))
	}
	// The failed message must not poison the next transaction on this connection.
	milterSend(t, client, 'M', 'c', []byte("<sender@example.org>\\x00"))
	milterSend(t, client, 'R', 'c', []byte("<recipient@example.org>\\x00"))
	milterSend(t, client, 'L', 'c', []byte("From\\x00sender@example.org\\x00"))
	milterSend(t, client, 'L', 'c', []byte("Subject\\x00normal status report\\x00"))
	milterSend(t, client, 'N', 'c', nil)
	milterSend(t, client, 'B', 'c', []byte("Normal body\\r\\n"))
	milterSend(t, client, 'E', 'c', nil)
	if messages := store.List(10, ""); len(messages) != 1 {
		t.Fatalf("valid subsequent transaction not recorded: %d", len(messages))
	}
	milterSend(t, client, 'Q', 0, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("milter handler did not stop")
	}
}
