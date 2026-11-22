package transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestUniqueSMTPRecipientsPreservesMailboxIdentity(t *testing.T) {
	input := []string{"Alice@example.org", "Alice@example.org", "alice@example.org", "bob+tag@example.org", "bob+tag@example.org"}
	got := uniqueSMTPRecipients(input)
	want := []string{"Alice@example.org", "alice@example.org", "bob+tag@example.org"}
	if len(got) != len(want) {
		t.Fatalf("got %q; want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
	if len(input) != 5 {
		t.Fatal("input envelope mutated")
	}
	if got := appendUniqueSMTPRecipient(nil, "a@example.org"); len(got) != 1 {
		t.Fatalf("first recipient not appended: %q", got)
	}
}

func TestRelayDoesNotTransmitDuplicateRCPT(t *testing.T) {
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
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		rd := bufio.NewReader(conn)
		if _, err := io.WriteString(conn, "220 relay.test ESMTP ready\r\n"); err != nil {
			done <- err
			return
		}
		var rcpts []string
		inData := false
		for {
			line, err := rd.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					if len(rcpts) != 2 || rcpts[0] != "a@example.org" || rcpts[1] != "b@example.org" {
						done <- fmt.Errorf("unexpected RCPT sequence %q", rcpts)
					} else {
						done <- nil
					}
				} else {
					done <- err
				}
				return
			}
			cmd := strings.TrimRight(line, "\r\n")
			if inData {
				if cmd == "." {
					inData = false
					_, err = io.WriteString(conn, "250 2.0.0 accepted\r\n")
				}
			} else {
				switch {
				case strings.HasPrefix(cmd, "EHLO "):
					_, err = io.WriteString(conn, "250-relay.test\r\n250-8BITMIME\r\n250 SIZE 10485760\r\n")
				case strings.HasPrefix(cmd, "MAIL FROM:"):
					_, err = io.WriteString(conn, "250 2.1.0 sender ok\r\n")
				case strings.HasPrefix(cmd, "RCPT TO:"):
					rcpts = append(rcpts, strings.TrimSuffix(strings.TrimPrefix(cmd, "RCPT TO:"), ""))
					_, err = io.WriteString(conn, "250 2.1.5 recipient ok\r\n")
				case cmd == "DATA":
					inData = true
					_, err = io.WriteString(conn, "354 send data\r\n")
				default:
					done <- fmt.Errorf("unexpected SMTP command %q", cmd)
					return
				}
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	relay := &Relay{Address: ln.Addr().String(), TLSMode: "none"}
	message := core.Message{Sender: "sender@example.org", Recipients: []string{"a@example.org", "a@example.org", "b@example.org"}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := relay.Send(ctx, message, []byte("From: sender@example.org\r\nTo: a@example.org\r\nSubject: recipient test\r\n\r\nbody\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay peer did not finish")
	}
}
