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

// Exercise the actual net/smtp client and a real TCP protocol exchange,
// rather than manufacturing only a textproto.Error in the queue tests.
func TestRelaySMTPResponseClassificationOverTCP(t *testing.T) {
	for _, tt := range []struct {
		name string
		rcptCode int
		dataCode int
		permanent bool
	}{
		{"recipient rejected", 550, 250, true},
		{"recipient temporarily unavailable", 451, 250, false},
		{"content rejected", 250, 554, true},
		{"accepted", 250, 250, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil { t.Fatal(err) }
			defer ln.Close()
			done := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil { done <- err; return }
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				write := func(format string, args ...any) error {
					_, err := fmt.Fprintf(conn, format, args...)
					return err
				}
				if err := write("220 local.test ESMTP ready\r\n"); err != nil { done <- err; return }
				inData := false
				for {
					line, err := reader.ReadString('\n')
					if err == io.EOF { done <- nil; return }
					if err != nil { done <- err; return }
					line = strings.TrimRight(line, "\r\n")
					if inData {
						if line == "." {
							inData = false
							if err := write("%d 2.0.0 DATA response\r\n", tt.dataCode); err != nil { done <- err; return }
						}
						continue
					}
					switch {
					case strings.HasPrefix(line, "EHLO "):
						err = write("250-local.test\r\n250 8BITMIME\r\n")
					case strings.HasPrefix(line, "MAIL FROM:"):
						err = write("250 2.1.0 OK\r\n")
					case strings.HasPrefix(line, "RCPT TO:"):
						err = write("%d 2.1.5 RCPT response\r\n", tt.rcptCode)
					case line == "DATA":
						inData = true
						err = write("354 Send data\r\n")
					case line == "QUIT":
						err = write("221 Bye\r\n")
						done <- err
						return
					default:
						done <- fmt.Errorf("unexpected SMTP command %q", line)
						return
					}
					if err != nil { done <- err; return }
				}
			}()
			relay := &Relay{Address: ln.Addr().String(), TLSMode: "none"}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = relay.Send(ctx, core.Message{
				Sender: "sender@example.invalid",
				Recipients: []string{"recipient@example.invalid"},
			}, []byte("Subject: relay test\r\n\r\nbody\r\n"))
			if tt.rcptCode == 250 && tt.dataCode == 250 {
				if err != nil { t.Fatalf("accepted SMTP message failed: %v", err) }
			} else if err == nil {
				t.Fatal("expected upstream SMTP error")
			}
			if got := isPermanentRelayFailure(err); got != tt.permanent {
				t.Fatalf("permanent=%t want %t; error=%v", got, tt.permanent, err)
			}
			select {
			case serverErr := <-done:
				if serverErr != nil { t.Fatalf("fake SMTP server: %v", serverErr) }
			case <-time.After(6*time.Second):
				t.Fatal("fake SMTP server did not exit")
			}
		})
	}
}
