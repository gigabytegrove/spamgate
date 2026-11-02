package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// A peer can advertise AUTH PLAIN while withholding STARTTLS. The relay
// must fail before transmitting AUTH or any message envelope, even if the
// peer is on loopback and Go's PlainAuth would otherwise permit cleartext.
func TestRelayDoesNotAuthenticateWhenSTARTTLSIsMissing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil { done <- err; return }
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, "220 relay.example ESMTP ready\r\n"); err != nil { done <- err; return }
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		if err != nil { done <- err; return }
		if !strings.HasPrefix(line, "EHLO ") { done <- fmt.Errorf("expected EHLO, got %q", line); return }
		if _, err := io.WriteString(conn, "250-relay.example\r\n250 AUTH PLAIN\r\n"); err != nil { done <- err; return }
		for {
			line, err := reader.ReadString('\n')
			if errors.Is(err, io.EOF) { done <- nil; return }
			if err != nil { done <- err; return }
			done <- fmt.Errorf("command sent without STARTTLS: %q", line)
			return
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	r := &Relay{Address: ln.Addr().String(), TLSMode: "required", Username: "user", Password: "not-on-the-wire"}
	err = r.Send(ctx, core.Message{Sender: "sender@example.org", Recipients: []string{"to@example.org"}}, []byte("Subject: test\r\n\r\nbody\r\n"))
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") { t.Fatalf("missing STARTTLS not refused: %v", err) }
	if strings.Contains(err.Error(), "not-on-the-wire") { t.Fatalf("credential leaked: %v", err) }
	select {
	case peerErr := <-done:
		if peerErr != nil { t.Fatalf("SMTP peer: %v", peerErr) }
	case <-time.After(5 * time.Second):
		t.Fatal("SMTP peer did not observe clean disconnect")
	}
}
