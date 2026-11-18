package smtpprobe

import (
 "context"
 "errors"
 "net"
 "testing"
 "time"
)

// A completed SMTP refusal must never inherit cancellation from probe cleanup.
func TestCompletedSMTPRefusalDoesNotBecomeCancellation(t *testing.T) {
 listener, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer listener.Close()
 done := make(chan struct{})
 go func() {
  defer close(done)
  conn, err := listener.Accept()
  if err != nil { return }
  defer conn.Close()
  _, _ = conn.Write([]byte("550 5.7.1 Rejected\r\n"))
 }()
 result, err := Probe(context.Background(), Options{Address:listener.Addr().String(), Timeout:time.Second})
 <-done
 var reply *SMTPReplyError
 if !errors.As(err, &reply) || reply.Code != 550 { t.Fatalf("expected typed SMTP refusal, got %v", err) }
 if result.FailureKind != "SMTP_PERMANENT_REJECTION" || result.FailureStage != "greeting" {
  t.Fatalf("incorrect classification: %+v", result)
 }
}

// A real caller cancellation during a stalled greeting must remain cancellation.
func TestStalledGreetingRetainsCallerCancellation(t *testing.T) {
 listener, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer listener.Close()
 accepted := make(chan struct{})
 done := make(chan struct{})
 go func() {
  defer close(done)
  conn, err := listener.Accept()
  if err != nil { close(accepted); return }
  defer conn.Close()
  close(accepted)
  var buf [1]byte
  _, _ = conn.Read(buf[:])
 }()
 ctx, cancel := context.WithCancel(context.Background())
 defer cancel()
 resultCh := make(chan struct { result Result; err error }, 1)
 go func() {
  result, err := Probe(ctx, Options{Address:listener.Addr().String(), Timeout:time.Second})
  resultCh <- struct { result Result; err error }{result, err}
 }()
 <-accepted
 cancel()
 select {
 case got := <-resultCh:
  if !errors.Is(got.err, context.Canceled) || got.result.FailureKind != "CANCELED" {
   t.Fatalf("expected cancellation: result=%+v err=%v", got.result, got.err)
  }
 case <-time.After(3*time.Second): t.Fatal("canceled probe failed to return")
 }
 <-done
}
