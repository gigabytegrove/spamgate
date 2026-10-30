package transport

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// The native queue supplies a bounded delivery context. A peer that accepts
// TCP but stalls the SMTP greeting must not hold the worker for the old
// unconditional 40-second socket deadline.
func TestRelayGreetingStallHonorsContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = io.Copy(io.Discard, conn)
		if errors.Is(err, io.EOF) || err == nil {
			done <- nil
		} else {
			done <- err
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Millisecond)
	defer cancel()
	start := time.Now()
	relay := &Relay{Address: ln.Addr().String(), TLSMode: "none"}
	err = relay.Send(ctx, core.Message{
		Sender: "sender@example.invalid", Recipients: []string{"to@example.invalid"},
	}, []byte("Subject: timeout\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("stalled SMTP greeting unexpectedly succeeded")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("SMTP greeting ignored context deadline: %v", elapsed)
	}
	select {
	case peerErr := <-done:
		if peerErr != nil {
			t.Fatalf("peer did not close cleanly: %v", peerErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SMTP peer connection not closed after deadline")
	}
}

// Cancellation must also interrupt an already-established SMTP transaction.
// A remote RCPT response may never arrive; no DATA may be transmitted.
func TestRelayRecipientStallHonorsCancellation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	rcptSeen := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = io.WriteString(conn, "220 relay.test ESMTP ready\r\n"); err != nil {
			done <- err
			return
		}
		reader := bufio.NewReader(conn)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr == io.EOF {
				done <- nil
				return
			}
			if readErr != nil {
				done <- readErr
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "):
				_, err = io.WriteString(conn, "250 relay.test\r\n")
			case strings.HasPrefix(line, "MAIL FROM:"):
				_, err = io.WriteString(conn, "250 sender accepted\r\n")
			case strings.HasPrefix(line, "RCPT TO:"):
				select {
				case rcptSeen <- struct{}{}:
				default:
				}
				// Deliberately do not respond. The client must cancel.
			case strings.HasPrefix(line, "DATA"):
				done <- errors.New("DATA sent after unacknowledged RCPT")
				return
			default:
				done <- errors.New("unexpected SMTP command: " + strings.TrimSpace(line))
				return
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		relay := &Relay{Address: ln.Addr().String(), TLSMode: "none"}
		finished <- relay.Send(ctx, core.Message{
			Sender: "sender@example.invalid", Recipients: []string{"to@example.invalid"},
		}, []byte("Subject: cancellation\r\n\r\nbody\r\n"))
	}()
	select {
	case <-rcptSeen:
		cancel()
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("relay did not reach RCPT")
	}
	select {
	case sendErr := <-finished:
		if sendErr == nil {
			t.Fatal("cancelled SMTP relay unexpectedly succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMTP relay ignored cancellation while awaiting RCPT")
	}
	select {
	case peerErr := <-done:
		if peerErr != nil {
			t.Fatalf("SMTP peer failed: %v", peerErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SMTP peer connection remained open after cancellation")
	}
}
