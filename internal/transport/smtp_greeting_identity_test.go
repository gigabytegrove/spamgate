package transport

import (
 "bufio"
 "fmt"
 "net"
 "strings"
 "testing"
 "time"
)

func TestSMTPGreetingIdentity(t *testing.T) {
 valid := []string{"localhost", "mail.example.org", "MAIL.Example.Org", "a-b.example", "[127.0.0.1]", "[IPv6:::1]", "[IPv6:2001:db8::1]"}
 invalid := []string{"", " ", "mail.example.org ", " mail.example.org", "mail example.org", "mail\t.example.org", "mail\r.example.org", "mail\n.example.org", "mail..example.org", ".example.org", "example.org.", "-mail.example", "mail-.example", "mail_example.org", "K.example", "[::1]", "[IPv6:127.0.0.1]", "[IPv6:fe80::1%eth0]", "[999.1.1.1]", "[IPv6:]", "[127.0.0.1", "127.0.0.1]", strings.Repeat("a",64)+".org", strings.Repeat("a",254)}
 for _, value := range valid {
  if !validSMTPGreetingIdentity(value) { t.Errorf("valid greeting refused: %q", value) }
 }
 for _, value := range invalid {
  if validSMTPGreetingIdentity(value) { t.Errorf("invalid greeting accepted: %q", value) }
 }
}

// A real loopback socket exercises the native command parser and its state
// transitions without a running mail server or a production data directory.
func TestSMTPGreetingRejectsMalformedIdentityWithoutChangingSession(t *testing.T) {
 listener, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer listener.Close()
 done := make(chan struct{})
 go func() {
  defer close(done)
  conn, acceptErr := listener.Accept()
  if acceptErr != nil { return }
  _, network, parseErr := net.ParseCIDR("127.0.0.0/8")
  if parseErr != nil { return }
  (&SMTP{CIDRs: []*net.IPNet{network}}).handle(conn)
 }()
 conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
 if err != nil { t.Fatal(err) }
 defer conn.Close()
 if err := conn.SetDeadline(time.Now().Add(4*time.Second)); err != nil { t.Fatal(err) }
 reader := bufio.NewReader(conn)
 expect := func(prefix string) {
  t.Helper()
  line, readErr := reader.ReadString('\n')
  if readErr != nil { t.Fatal(readErr) }
  if !strings.HasPrefix(line, prefix) { t.Fatalf("got %q, expected prefix %q", line, prefix) }
 }
 send := func(command string) {
  t.Helper()
  if _, writeErr := fmt.Fprintf(conn, "%s\r\n", command); writeErr != nil { t.Fatal(writeErr) }
 }
 expect("220 ")
 for _, command := range []string{"HELO bad_name", "EHLO example..org", "EHLO [::1]", "HELO mail example.org"} {
  send(command)
  expect("501 ")
 }
 send("MAIL FROM:<sender@example.org>")
 expect("503 ")
 send("HELO mail.example.org")
 expect("250 ")
 send("RSET")
 expect("250 ")
 send("QUIT")
 expect("221 ")
 select { case <-done: case <-time.After(2*time.Second): t.Fatal("handler did not terminate") }
}
