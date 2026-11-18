package smtpprobe

import (
 "context"
 "net"
 "strings"
 "testing"
 "time"
)

// Latency evidence must be present on both successful and failed probes,
// including failure before a TCP connection is established.
func TestProbeLatencyEvidence(t *testing.T) {
 t.Run("invalid configuration", func(t *testing.T) {
  r, err := Probe(context.Background(), Options{Timeout: 0})
  if err == nil || r.ProbeDurationMillis < 0 || r.TLSHandshakeMillis != 0 {
   t.Fatalf("invalid configuration latency: %+v, %v", r, err)
  }
 })
 t.Run("stalled greeting", func(t *testing.T) {
  ln, err := net.Listen("tcp", "127.0.0.1:0")
  if err != nil { t.Fatal(err) }
  defer ln.Close()
  done := make(chan struct{})
  go func() {
   defer close(done)
   c, e := ln.Accept()
   if e != nil { return }
   defer c.Close()
   var b [1]byte
   _, _ = c.Read(b[:])
  }()
  r, err := Probe(context.Background(), Options{Address:ln.Addr().String(), Timeout:40*time.Millisecond})
  if err == nil || r.FailureStage != "greeting" || r.ProbeDurationMillis < 1 || r.TLSHandshakeMillis != 0 {
   t.Fatalf("stalled greeting latency: %+v, %v", r, err)
  }
  if r.ProbeDurationMillis > 2000 { t.Fatalf("unexpectedly long diagnostic: %dms", r.ProbeDurationMillis) }
  _ = ln.Close()
  select { case <-done: case <-time.After(time.Second): t.Fatal("connection did not close") }
 })
 t.Run("successful plaintext observation", func(t *testing.T) {
  addr, commands := server(t, "250-test\r\n250 SIZE 1024\r\n")
  r, err := Probe(context.Background(), Options{Address:addr, Timeout:time.Second})
  if err != nil || r.EHLOCode != 250 || r.ProbeDurationMillis < 1 || r.TLSHandshakeMillis != 0 {
   t.Fatalf("successful probe latency: %+v, %v", r, err)
  }
  for cmd := range commands {
   if !strings.HasPrefix(cmd,"EHLO ") { t.Fatalf("unexpected command: %q",cmd) }
  }
 })
}
