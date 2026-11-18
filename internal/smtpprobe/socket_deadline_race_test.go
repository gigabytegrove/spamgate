package smtpprobe

import (
 "context"
 "errors"
 "net"
 "testing"
 "time"
)

// Repeatedly exercise the timer/socket deadline ordering. A socket deadline
// can fire just before the context timer publishes DeadlineExceeded.
func TestProbeSocketDeadlineRace(t *testing.T) {
 listener, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer listener.Close()
 done := make(chan struct{})
 go func() {
  defer close(done)
  for {
   conn, err := listener.Accept()
   if err != nil { return }
   go func(c net.Conn) {
    defer c.Close()
    var buf [1]byte
    _, _ = c.Read(buf[:])
   }(conn)
  }
 }()
 for i := 0; i < 5; i++ {
  result, err := Probe(context.Background(), Options{
   Address: listener.Addr().String(),
   Timeout: 35 * time.Millisecond,
  })
  if !errors.Is(err, context.DeadlineExceeded) {
   t.Fatalf("iteration %d: expected context deadline, got %v", i, err)
  }
  if result.FailureStage != "greeting" || result.FailureKind != "TIMEOUT" {
   t.Fatalf("iteration %d: unexpected evidence: %+v", i, result)
  }
 }
 if err := listener.Close(); err != nil { t.Fatal(err) }
 select {
 case <-done:
 case <-time.After(time.Second): t.Fatal("listener goroutine did not exit")
 }
}
