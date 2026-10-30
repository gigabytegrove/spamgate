package transport

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// Verify the real net/smtp client emits MAIL FROM:<> to the upstream relay.
// A queue callback that merely checks Message.Sender is not sufficient.
func TestRelayPreservesNullSMTPReversePathOnWire(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	observed := make(chan struct {
		mail, recipient, data string
		err error
	}, 1)
	go func() {
		var result struct {
			mail, recipient, data string
			err error
		}
		defer func() { observed <- result }()
		conn, err := listener.Accept()
		if err != nil {
			result.err = err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		reader := bufio.NewReader(conn)
		reply := func(line string) error {
			_, err := fmt.Fprint(conn, line)
			return err
		}
		if err := reply("220 test-relay ESMTP ready\r\n"); err != nil {
			result.err = err
			return
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				result.err = err
				return
			}
			upper := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(upper, "EHLO "):
				result.err = reply("250-test-relay\r\n250 8BITMIME\r\n")
			case strings.HasPrefix(upper, "MAIL FROM:"):
				result.mail = strings.TrimSpace(line)
				result.err = reply("250 2.1.0 sender accepted\r\n")
			case strings.HasPrefix(upper, "RCPT TO:"):
				result.recipient = strings.TrimSpace(line)
				result.err = reply("250 2.1.5 recipient accepted\r\n")
			case upper == "DATA":
				if result.err = reply("354 end with dot\r\n"); result.err != nil {
					return
				}
				var body strings.Builder
				for {
					line, err = reader.ReadString('\n')
					if err != nil {
						result.err = err
						return
					}
					if line == ".\r\n" || line == ".\n" {
						break
					}
					body.WriteString(line)
				}
				result.data = body.String()
				result.err = reply("250 2.0.0 queued\r\n")
			case upper == "QUIT":
				result.err = reply("221 2.0.0 bye\r\n")
				return
			default:
				result.err = fmt.Errorf("unexpected SMTP command %q", line)
				return
			}
			if result.err != nil {
				return
			}
		}
	}()
	relay := &Relay{Address: listener.Addr().String(), TLSMode: "none"}
	raw := []byte("From: human@example.org\r\nTo: recipient@example.net\r\nSubject: DSN\r\n\r\nStatus report\r\n")
	if err := relay.Send(context.Background(), core.Message{
		Sender: "", Recipients: []string{"recipient@example.net"},
	}, raw); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-observed:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !strings.HasPrefix(result.mail, "MAIL FROM:<>") {
			t.Fatalf("null reverse path rewritten on wire: %q", result.mail)
		}
		if result.recipient != "RCPT TO:<recipient@example.net>" {
			t.Fatalf("recipient changed on wire: %q", result.recipient)
		}
		if !strings.Contains(result.data, "Subject: DSN") {
			t.Fatalf("relay lost message bytes: %q", result.data)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("test relay did not complete")
	}
}
