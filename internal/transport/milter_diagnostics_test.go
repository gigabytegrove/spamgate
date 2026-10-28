package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestMilterReasonWhenAdministratorSetupIncomplete(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prior) })
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = serverSide.Close(); _ = clientSide.Close() })
	m := &Milter{Store: store, Scanner: &core.Scanner{Store: store, Resolver: milterStubDNS{}}}
	done := make(chan error, 1)
	go func() { done <- m.handle(context.Background(), serverSide) }()
	opts := make([]byte, 12)
	binary.BigEndian.PutUint32(opts[:4], 6)
	binary.BigEndian.PutUint32(opts[4:8], milterAddHeader|milterQuarantine)
	milterSend(t, clientSide, 'O', 'O', opts)
	milterSend(t, clientSide, 'M', 'c', []byte("<sender@example.com>\x00"))
	milterSend(t, clientSide, 'R', 'c', []byte("<receiver@example.org>\x00"))
	milterSend(t, clientSide, 'L', 'c', []byte("From\x00sender@example.com\x00"))
	milterSend(t, clientSide, 'N', 'c', nil)
	milterSend(t, clientSide, 'B', 'c', []byte("Testing\r\n"))
	milterSend(t, clientSide, 'E', 't', nil)
	if !strings.Contains(logs.String(), "administrator_setup_incomplete") {
		t.Fatalf("expected actionable diagnostic, got %q", logs.String())
	}
	milterSend(t, clientSide, 'Q', 0, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not shut down")
	}
}

func TestMilterReasonWhenScanFails(t *testing.T) {
	t.Setenv("SPAMGATE_CLAMAV_ADDRESS", "tcp://127.0.0.1:1")
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error { c.SetupComplete = true; return nil }); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prior) })
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() { _ = serverSide.Close(); _ = clientSide.Close() })
	m := &Milter{Store: store, Scanner: &core.Scanner{Store: store, Resolver: milterStubDNS{}}}
	done := make(chan error, 1)
	go func() { done <- m.handle(context.Background(), serverSide) }()
	opts := make([]byte, 12)
	binary.BigEndian.PutUint32(opts[:4], 6)
	binary.BigEndian.PutUint32(opts[4:8], milterAddHeader|milterQuarantine)
	milterSend(t, clientSide, 'O', 'O', opts)
	milterSend(t, clientSide, 'M', 'c', []byte("<sender@example.com>\x00"))
	milterSend(t, clientSide, 'R', 'c', []byte("<receiver@example.org>\x00"))
	milterSend(t, clientSide, 'L', 'c', []byte("From\x00sender@example.com\x00"))
	milterSend(t, clientSide, 'N', 'c', nil)
	milterSend(t, clientSide, 'B', 'c', []byte("Testing\r\n"))
	milterSend(t, clientSide, 'E', 't', nil)
	if !strings.Contains(logs.String(), "scan_failed") || !strings.Contains(logs.String(), "antivirus") {
		t.Fatalf("expected actionable scan diagnostic, got %q", logs.String())
	}
	milterSend(t, clientSide, 'Q', 0, nil)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("did not shut down")
	}
}
