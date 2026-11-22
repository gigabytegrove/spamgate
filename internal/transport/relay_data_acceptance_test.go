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

// A relay's final 250 after DATA is the acceptance boundary. An unresponsive
// QUIT response must not delay the worker or cause an upstream retry.
func TestRelayAcceptedDataDoesNotWaitForQuit(t *testing.T) {
 ln, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer ln.Close()
 done := make(chan error, 1)
 go func() {
  conn, err := ln.Accept()
  if err != nil { done <- err; return }
  defer conn.Close()
  _ = conn.SetDeadline(time.Now().Add(3*time.Second))
  rd := bufio.NewReader(conn)
  if _, err = io.WriteString(conn, "220 relay.test ESMTP ready\r\n"); err != nil { done <- err; return }
  inData := false
  for {
   line, e := rd.ReadString('\n')
   if e != nil {
    if e == io.EOF { done <- nil } else { done <- e }
    return
   }
   command := strings.TrimRight(line, "\r\n")
   if inData {
    if command == "." {
     inData = false
     if _, e = io.WriteString(conn, "250 2.0.0 queued\r\n"); e != nil { done <- e; return }
    }
    continue
   }
   upper := strings.ToUpper(command)
   switch {
   case strings.HasPrefix(upper, "EHLO "):
    _, e = io.WriteString(conn, "250-relay.test\r\n250-8BITMIME\r\n250 SIZE 10485760\r\n")
   case strings.HasPrefix(upper, "MAIL FROM:"), strings.HasPrefix(upper, "RCPT TO:"):
    _, e = io.WriteString(conn, "250 2.1.0 OK\r\n")
   case upper == "DATA":
    inData = true
    _, e = io.WriteString(conn, "354 Continue\r\n")
   case upper == "QUIT":
    // Intentionally never answer QUIT: waiting here is a correctness bug.
    time.Sleep(2*time.Second)
    done <- fmt.Errorf("client sent QUIT after accepted DATA")
    return
   default:
    done <- fmt.Errorf("unexpected SMTP command %q", command)
    return
   }
   if e != nil { done <- e; return }
  }
 }()
 relay := &Relay{Address: ln.Addr().String(), TLSMode: "none"}
 msg := core.Message{Sender: "sender@example.org", Recipients: []string{"recipient@example.org"}}
 ctx, cancel := context.WithTimeout(context.Background(), time.Second)
 defer cancel()
 start := time.Now()
 err = relay.Send(ctx, msg, []byte("From: sender@example.org\r\nTo: recipient@example.org\r\nSubject: accepted\r\n\r\nhello\r\n"))
 if err != nil { t.Fatalf("accepted DATA failed: %v", err) }
 if time.Since(start) > 900*time.Millisecond { t.Fatal("accepted DATA was delayed by connection shutdown") }
 select {
 case peerErr := <-done:
  if peerErr != nil { t.Fatal(peerErr) }
 case <-time.After(3*time.Second):
  t.Fatal("relay peer did not observe connection closure")
 }
}
