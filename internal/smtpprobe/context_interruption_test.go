package smtpprobe

import (
 "context"
 "errors"
 "net"
 "testing"
 "time"
)

// A peer that accepts TCP but never sends its greeting exercises the socket
// close initiated by the probe's context cancellation callback.
func TestProbeStalledGreetingDeadlineIsTimeout(t *testing.T) {
 listener, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer listener.Close()
 accepted := make(chan struct{})
 done := make(chan struct{})
 go func() {
  defer close(done)
  conn, e := listener.Accept()
  if e != nil { close(accepted); return }
  defer conn.Close()
  close(accepted)
  var b [1]byte
  _, _ = conn.Read(b[:])
 }()
 result, err := Probe(context.Background(), Options{
  Address: listener.Addr().String(), Timeout: 80*time.Millisecond,
 })
 <-accepted
 if !errors.Is(err, context.DeadlineExceeded) {
  t.Fatalf("expected deadline exceeded, got %v", err)
 }
 if result.FailureStage != "greeting" || result.FailureKind != "TIMEOUT" {
  t.Fatalf("incorrect timeout evidence: %+v", result)
 }
 select {
 case <-done:
 case <-time.After(time.Second): t.Fatal("connection not closed after deadline")
 }
}

func TestProbeStalledGreetingCanceledByCaller(t *testing.T) {
 listener, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer listener.Close()
 accepted := make(chan struct{})
 done := make(chan struct{})
 go func() {
  defer close(done)
  conn, e := listener.Accept()
  if e != nil { close(accepted); return }
  defer conn.Close()
  close(accepted)
  var b [1]byte
  _, _ = conn.Read(b[:])
 }()
 ctx, cancel := context.WithCancel(context.Background())
 defer cancel()
 go func() { <-accepted; cancel() }()
 result, err := Probe(ctx, Options{
  Address: listener.Addr().String(), Timeout: 3*time.Second,
 })
 if !errors.Is(err, context.Canceled) {
  t.Fatalf("expected cancellation, got %v", err)
 }
 // TCP Accept may succeed before DialContext returns. Caller cancellation
 // at that boundary is legitimately connection-stage, not greeting-stage.
 if (result.FailureStage != "greeting" && result.FailureStage != "connection") || result.FailureKind != "CANCELED" {
  t.Fatalf("incorrect cancellation evidence: %+v", result)
 }
 select {
 case <-done:
 case <-time.After(time.Second): t.Fatal("connection not closed after cancellation")
 }
}
