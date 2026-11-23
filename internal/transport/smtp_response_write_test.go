package transport

import (
 "bufio"
 "errors"
 "io"
 "net"
 "strings"
 "testing"
 "time"
)

func TestSMTPResponseAfterExpiredReadDeadline(t *testing.T) {
 server, peer := net.Pipe()
 defer server.Close()
 defer peer.Close()
 if err := server.SetReadDeadline(time.Now().Add(-time.Second)); err != nil { t.Fatal(err) }
 result := make(chan error, 1)
 go func() { result <- smtpWriteResponse(server, bufio.NewWriter(server), "421 4.4.2 Timeout\r\n") }()
 data := make([]byte, 128)
 if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil { t.Fatal(err) }
 n, err := peer.Read(data)
 if err != nil { t.Fatal(err) }
 if string(data[:n]) != "421 4.4.2 Timeout\r\n" { t.Fatalf("reply = %q", data[:n]) }
 if err := <-result; err != nil { t.Fatal(err) }
}

func TestSMTPResponseRefreshesExpiredWriteDeadline(t *testing.T) {
 server, peer := net.Pipe()
 defer server.Close()
 defer peer.Close()
 if err := server.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil { t.Fatal(err) }
 done := make(chan error, 1)
 go func() { done <- smtpWriteResponse(server, bufio.NewWriter(server), "250 Ready\r\n") }()
 if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil { t.Fatal(err) }
 got, err := bufio.NewReader(peer).ReadString('\n')
 if err != nil { t.Fatal(err) }
 if got != "250 Ready\r\n" { t.Fatalf("reply = %q", got) }
 if err := <-done; err != nil { t.Fatal(err) }
}

func TestSMTPResponseBlockedPeerTimesOut(t *testing.T) {
 server, peer := net.Pipe()
 defer server.Close()
 defer peer.Close()
 if err := peer.SetReadDeadline(time.Now().Add(20*time.Millisecond)); err != nil { t.Fatal(err) }
 // Force an already-expired write deadline after the helper starts by
 // waiting for its bounded deadline, without waiting five seconds in tests.
 // A closed peer must fail promptly rather than silently succeeding.
 _ = peer.Close()
 err := smtpWriteResponse(server, bufio.NewWriter(server), strings.Repeat("X", 1024))
 if err == nil || !errors.Is(err, io.ErrClosedPipe) {
  t.Fatalf("expected closed pipe, got %v", err)
 }
}
