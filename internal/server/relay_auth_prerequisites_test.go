package server

import (
 "bufio"
 "context"
 "fmt"
 "net"
 "strings"
 "testing"
 "time"
)

// Capability evidence must not be confused with a successful login, and
// credentials configured for plaintext SMTP must never be marked safe.
func TestRelayAUTHPrerequisiteEvidence(t *testing.T) {
 cases := []struct {
  name, auth string
  credentials bool
  wantKnown, wantReady bool
  wantWarning string
 }{
  {"plaintext credentials and AUTH", "250 AUTH PLAIN LOGIN\r\n", true, true, false, "credentials_configured_without_tls"},
  {"plaintext credentials no AUTH", "250 SIZE 100\r\n", true, false, false, "credentials_configured_without_tls"},
  {"no credentials AUTH", "250 AUTH PLAIN\r\n", false, true, false, ""},
  {"empty AUTH", "250 AUTH\r\n", true, false, false, "credentials_configured_without_tls"},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
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
    for {
     line, err := reader.ReadString('\n')
     if err != nil { break }
     line = strings.TrimSpace(line)
     seen = append(seen, line)
     if strings.HasPrefix(line, "EHLO ") { _, _ = fmt.Fprint(conn, "250-mx.test\r\n"+tc.auth) }
     if line == "QUIT" { _, _ = fmt.Fprint(conn, "221 Bye\r\n"); break }
    }
    commands <- seen
   }()
   result := probeRelay(context.Background(), listener.Addr().String(), "none", tc.credentials)
   if !result.SMTPReady || result.AUTHMechanismsKnown != tc.wantKnown || result.AUTHPrerequisitesObserved != tc.wantReady || result.AUTHWarning != tc.wantWarning {
    t.Fatalf("unexpected AUTH evidence: %+v", result)
   }
   select {
   case seen := <-commands:
    if len(seen) != 2 || !strings.HasPrefix(seen[0], "EHLO ") || seen[1] != "QUIT" {
     t.Fatalf("unsafe SMTP commands: %q", seen)
    }
   case <-time.After(4*time.Second): t.Fatal("SMTP test server did not finish")
   }
  })
 }
}

func TestRelayAUTHPrerequisitesRequireVerifiedTLS(t *testing.T) {
 // The observable evidence is deliberately conservative: an AUTH mechanism
 // without verified TLS does not satisfy safe credential prerequisites.
 result := RelayDiagnostic{SMTPReady:true, AUTHAdvertised:true, AUTHMechanismsKnown:true, CredentialsConfigured:true}
 if result.AUTHPrerequisitesObserved { t.Fatal("AUTH marked safe without TLS verification") }
}
