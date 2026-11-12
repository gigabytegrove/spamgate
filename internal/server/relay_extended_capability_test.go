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

// The diagnostic is intentionally observational: EHLO advertisements are not
// proof that the server will accept an envelope, BDAT, or delivery.
func TestRelayExtendedCapabilityEvidence(t *testing.T) {
 ln, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer ln.Close()
 commands := make(chan []string, 1)
 go func() {
  conn, err := ln.Accept()
  if err != nil { commands <- nil; return }
  defer conn.Close()
  _ = conn.SetDeadline(time.Now().Add(4*time.Second))
  _, _ = fmt.Fprint(conn, "220 mx.example ESMTP\r\n")
  reader := bufio.NewReader(conn)
  var seen []string
  for {
   line, err := reader.ReadString('\n')
   if err != nil { break }
   line = strings.TrimSpace(line)
   seen = append(seen, line)
   switch {
   case strings.HasPrefix(line, "EHLO "):
    _, _ = fmt.Fprint(conn, "250-mx.example\r\n250-DSN\r\n250-CHUNKING\r\n250-BINARYMIME\r\n250-REQUIRETLS\r\n250-ENHANCEDSTATUSCODES\r\n250 PIPELINING\r\n")
   case line == "QUIT":
    _, _ = fmt.Fprint(conn, "221 bye\r\n")
   }
   if line == "QUIT" { break }
  }
  commands <- seen
 }()
 got := probeRelay(context.Background(), ln.Addr().String(), "none", false)
 if !got.SMTPReady || !got.DSNAdvertised || !got.CHUNKINGAdvertised || !got.BINARYMIMEAdvertised || !got.REQUIRETLSAdvertised || !got.EnhancedStatusCodesAdvertised || !got.PIPELININGAdvertised {
  t.Fatalf("missing advertised capabilities: %+v", got)
 }
 select {
 case seen := <-commands:
  if len(seen) != 2 || !strings.HasPrefix(seen[0], "EHLO ") || seen[1] != "QUIT" { t.Fatalf("unexpected commands: %q", seen) }
 case <-time.After(5*time.Second):
  t.Fatal("SMTP probe did not finish")
 }
}

func TestRelayExtensionIdentityAndMalformedTokens(t *testing.T) {
 ext := relayExtensions("DSN CHUNKING REQUIRETLS\nDSN\nCHUNKING\nBINARYMIME\nREQUIRETLS\nENHANCEDSTATUSCODES\nBAD/KEY\nINJECTED:KEY")
 for _, key := range []string{"DSN", "CHUNKING", "BINARYMIME", "REQUIRETLS", "ENHANCEDSTATUSCODES"} {
  if !ext[key] { t.Fatalf("missing %s", key) }
 }
 if ext["BAD/KEY"] || ext["INJECTED:KEY"] { t.Fatalf("malformed extension accepted: %#v", ext) }
 if relayExtensions("DSN CHUNKING REQUIRETLS")["DSN"] { t.Fatal("identity line was treated as extension") }
}
