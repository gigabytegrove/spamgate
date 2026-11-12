package server

import (
 "bufio"
 "fmt"
 "net"
 "net/textproto"
 "strings"
 "testing"
 "time"
)

// A failed EHLO must return the full diagnostic tuple and must not reinterpret
// an SMTP rejection as a successful extension advertisement.
func TestRelayEHLODetailsRejectedResponse(t *testing.T) {
 for _, tc := range []struct{name, response string}{
  {"permanent rejection", "550 5.5.1 EHLO unavailable\r\n"},
  {"temporary rejection", "421 4.3.2 service unavailable\r\n"},
  {"malformed response", "not an SMTP reply\r\n"},
 } {
  t.Run(tc.name, func(t *testing.T) {
   listener, err := net.Listen("tcp", "127.0.0.1:0")
   if err != nil { t.Fatal(err) }
   defer listener.Close()
   done := make(chan string, 1)
   go func() {
    conn, err := listener.Accept()
    if err != nil { done <- ""; return }
    defer conn.Close()
    _ = conn.SetDeadline(time.Now().Add(3*time.Second))
    reader := bufio.NewReader(conn)
    line, _ := reader.ReadString('\n')
    _, _ = fmt.Fprint(conn, tc.response)
    done <- strings.TrimSpace(line)
   }()
   conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
   if err != nil { t.Fatal(err) }
   defer conn.Close()
   _ = conn.SetDeadline(time.Now().Add(3*time.Second))
   extensions, mechanisms, limit, malformed, warnings, err := relayEHLODetails(textproto.NewConn(conn))
   if err == nil { t.Fatal("rejected EHLO accepted") }
   if extensions != nil || mechanisms != nil || limit != nil || malformed || warnings != nil {
    t.Fatalf("rejected EHLO returned partial capabilities: %v %v %v %v %v", extensions, mechanisms, limit, malformed, warnings)
   }
   select {
   case command := <-done:
    if command != "EHLO spamgate.local" { t.Fatalf("unexpected SMTP command: %q", command) }
   case <-time.After(4*time.Second): t.Fatal("server did not complete")
   }
  })
 }
}

// The probe must not claim SMTP readiness when the server rejects EHLO,
// even if the connection and SMTP greeting succeeded.
func TestProbeRelayEHLORejectionDoesNotSubmitMail(t *testing.T) {
 listener, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer listener.Close()
 commands := make(chan []string, 1)
 go func() {
  conn, err := listener.Accept()
  if err != nil { commands <- nil; return }
  defer conn.Close()
  _ = conn.SetDeadline(time.Now().Add(3*time.Second))
  _, _ = fmt.Fprint(conn, "220 mx.test ESMTP\r\n")
  reader := bufio.NewReader(conn)
  var seen []string
  line, err := reader.ReadString('\n')
  if err == nil {
   seen = append(seen, strings.TrimSpace(line))
   _, _ = fmt.Fprint(conn, "550 5.5.1 EHLO denied\r\n")
  }
  commands <- seen
 }()
 result := probeRelay(t.Context(), listener.Addr().String(), "none", true)
 if !result.TCPReachable || result.SMTPReady || result.AUTHAdvertised || result.TLSVerified {
  t.Fatalf("rejected EHLO was misreported: %+v", result)
 }
 if !strings.Contains(result.Detail, "EHLO failed") { t.Fatalf("missing failure detail: %q", result.Detail) }
 select {
 case seen := <-commands:
  if len(seen) != 1 || seen[0] != "EHLO spamgate.local" { t.Fatalf("unexpected commands: %q", seen) }
 case <-time.After(4*time.Second): t.Fatal("server did not complete")
 }
}
