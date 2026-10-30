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

type capabilityProbeResult struct {
	commands []string
	err      error
}

// A real TCP SMTP peer proves that preflight failures happen before MAIL
// FROM, not after partial RCPT acceptance or DATA transfer.
func TestRelayCapabilityPreflightOverTCP(t *testing.T) {
	for _, tt := range []struct {
		name       string
		extensions []string
		sender     string
		recipient  string
		raw        string
		wantError  string
		wantMail   bool
	}{
		{"ASCII with legacy EHLO", nil, "sender@example.invalid", "recipient@example.invalid", "Subject: test\r\n\r\nplain\r\n", "", true},
		{"eight bit without 8BITMIME", nil, "sender@example.invalid", "recipient@example.invalid", "Subject: test\r\n\r\ncaf\xc3\xa9\r\n", "8BITMIME", false},
		{"eight bit with 8BITMIME", []string{"8BITMIME"}, "sender@example.invalid", "recipient@example.invalid", "Subject: test\r\n\r\ncaf\xc3\xa9\r\n", "", true},
		{"UTF8 recipient without SMTPUTF8", []string{"8BITMIME"}, "sender@example.invalid", "b\xc3\xbcro@example.invalid", "Subject: test\r\n\r\nplain\r\n", "SMTPUTF8", false},
		{"UTF8 recipient with SMTPUTF8", []string{"8BITMIME", "SMTPUTF8"}, "sender@example.invalid", "b\xc3\xbcro@example.invalid", "Subject: test\r\n\r\nplain\r\n", "", true},
		{"upstream SIZE too small", []string{"SIZE 20"}, "sender@example.invalid", "recipient@example.invalid", "Subject: test\r\n\r\nbody longer than twenty bytes\r\n", "SIZE", false},
		{"upstream SIZE adequate", []string{"SIZE 4096"}, "sender@example.invalid", "recipient@example.invalid", "Subject: test\r\n\r\nplain\r\n", "", true},
		{"upstream SIZE malformed", []string{"SIZE nope"}, "sender@example.invalid", "recipient@example.invalid", "Subject: test\r\n\r\nplain\r\n", "malformed", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			done := make(chan capabilityProbeResult, 1)
			go func() {
				result := capabilityProbeResult{}
				defer func() { done <- result }()
				conn, err := ln.Accept()
				if err != nil {
					result.err = err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				reader := bufio.NewReader(conn)
				if _, err = io.WriteString(conn, "220 relay.test ESMTP ready\r\n"); err != nil {
					result.err = err
					return
				}
				inData := false
				for {
					line, readErr := reader.ReadString('\n')
					if errors.Is(readErr, io.EOF) {
						return
					}
					if readErr != nil {
						result.err = readErr
						return
					}
					line = strings.TrimRight(line, "\r\n")
					if inData {
						if line == "." {
							inData = false
							_, err = io.WriteString(conn, "250 2.0.0 Accepted\r\n")
							if err != nil {
								result.err = err
								return
							}
						}
						continue
					}
					result.commands = append(result.commands, line)
					switch {
					case strings.HasPrefix(line, "EHLO "):
						if len(tt.extensions) == 0 {
							_, err = io.WriteString(conn, "250 relay.test\r\n")
						} else {
							_, err = io.WriteString(conn, "250-relay.test\r\n")
							for i, extension := range tt.extensions {
								if err != nil {
									break
								}
								separator := "-"
								if i == len(tt.extensions)-1 {
									separator = " "
								}
								_, err = fmt.Fprintf(conn, "250%s%s\r\n", separator, extension)
							}
						}
					case strings.HasPrefix(line, "HELO "):
						_, err = io.WriteString(conn, "250 relay.test\r\n")
					case strings.HasPrefix(line, "MAIL FROM:"):
						_, err = io.WriteString(conn, "250 2.1.0 OK\r\n")
					case strings.HasPrefix(line, "RCPT TO:"):
						_, err = io.WriteString(conn, "250 2.1.5 OK\r\n")
					case line == "DATA":
						inData = true
						_, err = io.WriteString(conn, "354 Send data\r\n")
					case line == "QUIT":
						_, err = io.WriteString(conn, "221 2.0.0 Bye\r\n")
						result.err = err
						return
					default:
						result.err = fmt.Errorf("unexpected SMTP command %q", line)
						return
					}
					if err != nil {
						result.err = err
						return
					}
				}
			}()

			relay := &Relay{Address: ln.Addr().String(), TLSMode: "none"}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			sendErr := relay.Send(ctx, core.Message{
				Sender: tt.sender, Recipients: []string{tt.recipient},
			}, []byte(tt.raw))
			if tt.wantError == "" && sendErr != nil {
				t.Fatalf("expected delivery, got %v", sendErr)
			}
			if tt.wantError != "" && (sendErr == nil || !strings.Contains(sendErr.Error(), tt.wantError)) {
				t.Fatalf("expected error containing %q, got %v", tt.wantError, sendErr)
			}
			select {
			case result := <-done:
				if result.err != nil {
					t.Fatalf("fake SMTP relay: %v", result.err)
				}
				mailSeen := false
				for _, command := range result.commands {
					if strings.HasPrefix(command, "MAIL FROM:") {
						mailSeen = true
					}
				}
				if mailSeen != tt.wantMail {
					t.Fatalf("MAIL FROM sent=%t, want %t; commands=%q", mailSeen, tt.wantMail, result.commands)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("SMTP relay peer did not finish")
			}
		})
	}
}
