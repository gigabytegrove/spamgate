package transport

import (
 "context"
 "io"
 "log/slog"
 "net"
 "testing"
 "time"
)

func TestNativeSMTPLoggerFallback(t *testing.T) {
 defaultLogger := slog.Default()
 if got := (*SMTP)(nil).logger(); got != defaultLogger { t.Fatal("nil receiver must use default logger") }
 if got := (&SMTP{}).logger(); got != defaultLogger { t.Fatal("nil logger must use default logger") }
 custom := slog.New(slog.NewTextHandler(io.Discard, nil))
 if got := (&SMTP{log:custom}).logger(); got != custom { t.Fatal("custom logger must be retained") }
}

// The handler is also invoked directly by integration harnesses. Missing
// logger injection must not cause a panic before refusing an untrusted peer.
func TestNativeSMTPHandlerWithoutLoggerRejectsUntrustedPeer(t *testing.T) {
 server, client := net.Pipe()
 defer client.Close()
 done := make(chan struct{})
 go func(){ defer close(done); (&SMTP{}).handle(server) }()
 _ = client.SetReadDeadline(time.Now().Add(2*time.Second))
 buf := make([]byte, 256)
 n, err := client.Read(buf)
 if err != nil { t.Fatalf("expected SMTP rejection: %v",err) }
 if n < 3 || string(buf[:3]) != "554" { t.Fatalf("expected 554, got %q",buf[:n]) }
 select { case <-done: case <-time.After(2*time.Second): t.Fatal("handler did not exit") }
}

func TestNativeSMTPListenerCancelledContextDoesNotBypassPreflight(t *testing.T) {
 ctx,cancel:=context.WithCancel(context.Background())
 cancel()
 smtp := &SMTP{}
 if err:=smtp.Listen(ctx); err==nil { t.Fatal("missing durable dependencies must fail even on cancelled context") }
}
