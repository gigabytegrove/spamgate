package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func testSMTPListener(t *testing.T, advertiseTLS bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				fmt.Fprint(conn, "220 test.local ESMTP ready\r\n")
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO"):
						if advertiseTLS {
							fmt.Fprint(conn, "250-test.local\r\n250 STARTTLS\r\n")
						} else {
							fmt.Fprint(conn, "250 test.local\r\n")
						}
					case strings.HasPrefix(line, "QUIT"):
						fmt.Fprint(conn, "221 goodbye\r\n")
						return
					default:
						fmt.Fprint(conn, "500 unsupported\r\n")
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}
func TestRelayProbeSMTPAndRequiredTLS(t *testing.T) {
	addr := testSMTPListener(t, false)
	plain := probeRelay(context.Background(), addr, "none", false)
	if !plain.TCPReachable || !plain.SMTPReady || plain.TLSVerified || !strings.Contains(plain.Detail, "EHLO succeeded") {
		t.Fatalf("unexpected plain result: %+v", plain)
	}
	required := probeRelay(context.Background(), addr, "required", false)
	if !required.TCPReachable || required.SMTPReady || required.TLSVerified || !strings.Contains(required.Detail, "required STARTTLS") {
		t.Fatalf("TLS misclassified: %+v", required)
	}
	malformed := probeRelay(context.Background(), "invalid", "required", false)
	if malformed.TCPReachable || malformed.SMTPReady {
		t.Fatal("malformed endpoint passed")
	}
}
