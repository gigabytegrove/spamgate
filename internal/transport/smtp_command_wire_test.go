package transport

import (
 "bufio"
 "fmt"
 "net"
 "strings"
 "testing"
 "time"
)

func TestSMTPCommandWireValidation(t *testing.T) {
 valid := []string{"EHLO mail.example.org", "MAIL FROM:<sender@example.org> SIZE=42", "RCPT TO:<user@example.org>", "XFORWARD ADDR=192.0.2.10 HELO=mx.example.org", "DATA", "QUIT"}
 invalid := []string{"", " ", " HELO example.org", "HELO example.org ", "HELO  example.org", "MAIL  FROM:<a@example.org>", "MAIL FROM:<a@example.org> ", "QUIT ", "QUIT\\t", "HELO\\tmail.example.org", "EHLO mail.example.org\\r", "EHLO mail.example.org\\n", "EHLO K.example", "M4IL FROM:<a@example.org>", "MAIL  ", strings.Repeat("A", 513)}
 for _, command := range valid { if !validSMTPCommandWire(command) { t.Errorf("valid command rejected: %q", command) } }
 for _, command := range invalid {
  command = strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(command, "\\t", "\\t"), "\\r", "\\r"), "\\n", "\\n")
  if validSMTPCommandWire(command) { t.Errorf("malformed command accepted: %q", command) }
 }
}

func TestSMTPMalformedCommandCannotChangeEnvelope(t *testing.T) {
 listener, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer listener.Close()
 done := make(chan struct{})
 go func() {
  defer close(done)
  c, e := listener.Accept()
  if e != nil { return }
  _, cidr, _ := net.ParseCIDR("127.0.0.0/8")
  (&SMTP{CIDRs: []*net.IPNet{cidr}}).handle(c)
 }()
 c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
 if err != nil { t.Fatal(err) }
 defer c.Close()
 if err := c.SetDeadline(time.Now().Add(5*time.Second)); err != nil { t.Fatal(err) }
 reader := bufio.NewReader(c)
 expect := func(prefix string) {
  t.Helper()
  line, e := reader.ReadString('\\n')
  if e != nil { t.Fatal(e) }
  if !strings.HasPrefix(line, prefix) { t.Fatalf("got %q, want %q", line, prefix) }
 }
 send := func(command string) {
  t.Helper()
  if _, e := fmt.Fprintf(c, "%s\\r\\n", command); e != nil { t.Fatal(e) }
 }
 expect("220 ")
 for _, command := range []string{" EHLO mail.example.org", "EHLO  mail.example.org", "EHLO mail.example.org ", "EHLO\\tmail.example.org"} {
  send(command)
  expect("500 ")
 }
 send("MAIL FROM:<sender@example.org>")
 expect("503 ")
 send("EHLO mail.example.org")
 expect("250-")
 expect("250-")
 expect("250-")
 expect("250 ")
 for _, command := range []string{" MAIL FROM:<sender@example.org>", "MAIL  FROM:<sender@example.org>", "MAIL FROM:<sender@example.org> "} {
  send(command)
  expect("500 ")
 }
 send("RCPT TO:<user@example.org>")
 expect("503 ")
 send("QUIT")
 expect("221 ")
 select { case <-done: case <-time.After(2*time.Second): t.Fatal("handler leaked") }
}
