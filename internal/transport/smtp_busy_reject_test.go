package transport

import (
 "net"
 "sync"
 "testing"
 "time"
)

func TestRejectBusySMTPConnectionDoesNotWaitForPeerRead(t *testing.T) {
 server, client := net.Pipe()
 defer client.Close()
 done := make(chan struct{})
 go func() { rejectBusySMTPConnection(server); close(done) }()
 select {
 case <-done:
 case <-time.After(time.Second):
  t.Fatal("saturated listener blocked while writing to non-reading peer")
 }
 _ = client.SetReadDeadline(time.Now().Add(time.Second))
 var buf [1]byte
 if n, err := client.Read(buf[:]); n != 0 || err == nil {
  t.Fatalf("expected immediate EOF after overload rejection; n=%d err=%v", n, err)
 }
}

func TestRejectBusySMTPConnectionConcurrent(t *testing.T) {
 const count = 128
 var wg sync.WaitGroup
 for i := 0; i < count; i++ {
  server, client := net.Pipe()
  wg.Add(1)
  go func() {
   defer wg.Done()
   rejectBusySMTPConnection(server)
   client.Close()
  }()
 }
 done := make(chan struct{})
 go func(){wg.Wait();close(done)}()
 select {
 case <-done:
 case <-time.After(2*time.Second):
  t.Fatal("overload rejection goroutines stalled")
 }
}

func TestRejectBusySMTPConnectionNil(t *testing.T) {
 rejectBusySMTPConnection(nil)
}
