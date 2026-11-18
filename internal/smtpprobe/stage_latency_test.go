package smtpprobe

import (
 "bufio"
 "context"
 "encoding/json"
 "net"
 "strings"
 "testing"
 "time"
)

// These tests exercise the actual TCP probe rather than a fabricated Result.
func TestSMTPStageLatencyEvidence(t *testing.T) {
 ln, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer ln.Close()
 done := make(chan error, 1)
 go func() {
  conn, err := ln.Accept()
  if err != nil { done <- err; return }
  defer conn.Close()
  time.Sleep(25*time.Millisecond)
  if _, err = conn.Write([]byte("220 localhost ESMTP ready\r\n")); err != nil { done <- err; return }
  reader := bufio.NewReader(conn)
  line, err := reader.ReadString('\n')
  if err != nil { done <- err; return }
  if !strings.HasPrefix(line, "EHLO ") { done <- context.Canceled; return }
  time.Sleep(25*time.Millisecond)
  _, err = conn.Write([]byte("250-localhost\r\n250 SIZE 4096\r\n"))
  done <- err
 }()
 r, err := Probe(context.Background(), Options{Address:ln.Addr().String(), Timeout:time.Second})
 if err != nil { t.Fatal(err) }
 if r.GreetingDurationMillis < 20 || r.EHLORoundTripMillis < 20 {
  t.Fatalf("stage measurements missing expected delays: %+v", r)
 }
 if r.ProbeDurationMillis < r.GreetingDurationMillis || r.ProbeDurationMillis < r.EHLORoundTripMillis {
  t.Fatalf("total duration less than stage: %+v", r)
 }
 if r.StartTLSRoundTripMillis != 0 || r.PostTLSEHLORoundTripMillis != 0 || r.TLSHandshakeMillis != 0 {
  t.Fatalf("unattempted TLS stages must remain zero: %+v", r)
 }
 encoded, err := json.Marshal(r)
 if err != nil { t.Fatal(err) }
 for _, key := range []string{"probe_duration_ms", "greeting_duration_ms", "ehlo_round_trip_ms"} {
  if !strings.Contains(string(encoded), "\"" + key + "\"") { t.Fatalf("missing %s in JSON", key) }
 }
 select { case err := <-done: if err != nil { t.Fatal(err) }; case <-time.After(time.Second): t.Fatal("server did not complete") }
}

func TestSMTPStageLatencyOnGreetingTimeout(t *testing.T) {
 ln, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer ln.Close()
 done := make(chan struct{})
 go func() {
  defer close(done)
  conn, err := ln.Accept()
  if err != nil { return }
  defer conn.Close()
  var b [1]byte
  _, _ = conn.Read(b[:])
 }()
 r, err := Probe(context.Background(), Options{Address:ln.Addr().String(), Timeout:35*time.Millisecond})
 if err == nil || r.FailureStage != "greeting" || r.GreetingDurationMillis < 1 {
  t.Fatalf("greeting timeout did not retain timing: %+v, %v", r, err)
 }
 if r.EHLORoundTripMillis != 0 || r.StartTLSRoundTripMillis != 0 || r.PostTLSEHLORoundTripMillis != 0 {
  t.Fatalf("unattempted stages reported durations: %+v", r)
 }
 select { case <-done: case <-time.After(time.Second): t.Fatal("probe did not close connection") }
}
