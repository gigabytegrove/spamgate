package transport

import (
 "bufio"
 "fmt"
 "io"
 "net"
 "net/smtp"
 "strings"
 "testing"
 "time"
)

func TestRequireRelayPlainAuth(t *testing.T) {
 cases := []struct{name string; extensions []string; allowed bool}{
  {"no AUTH", nil, false},
  {"LOGIN only", []string{"AUTH LOGIN"}, false},
  {"CRAM-MD5 only", []string{"AUTH CRAM-MD5"}, false},
  {"PLAIN", []string{"AUTH PLAIN"}, true},
  {"multiple mechanisms", []string{"AUTH LOGIN PLAIN CRAM-MD5"}, true},
  {"mixed case", []string{"AUTH login plain"}, true},
  {"lookalike", []string{"AUTH XPLAIN"}, false},
  {"other extension", []string{"SIZE 1000"}, false},
 }
 for _, tc := range cases { t.Run(tc.name, func(t *testing.T) {
  ln, err := net.Listen("tcp", "127.0.0.1:0"); if err != nil { t.Fatal(err) }; defer ln.Close()
  done := make(chan error, 1)
  go func() {
   conn, err := ln.Accept(); if err != nil { done <- err; return }; defer conn.Close()
   _ = conn.SetDeadline(time.Now().Add(3*time.Second))
   if _, err = io.WriteString(conn, "220 relay.test ESMTP ready\r\n"); err != nil { done <- err; return }
   reader := bufio.NewReader(conn)
   line, err := reader.ReadString('\n'); if err != nil { done <- err; return }
   if !strings.HasPrefix(line, "EHLO ") { done <- fmt.Errorf("expected EHLO, got %q", line); return }
   if len(tc.extensions)==0 { _, err = io.WriteString(conn, "250 relay.test\r\n") } else {
    _, err = io.WriteString(conn, "250-relay.test\r\n")
    for i, ext := range tc.extensions { if err != nil { break }; sep := "-"; if i == len(tc.extensions)-1 { sep = " " }; _, err = fmt.Fprintf(conn, "250%s%s\r\n", sep, ext) }
   }
   if err != nil { done <- err; return }
   line, err = reader.ReadString('\n'); if err == io.EOF { done <- nil; return }; if err != nil { done <- err; return }
   done <- fmt.Errorf("unexpected SMTP command %q", line)
  }()
  conn, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); if err != nil { t.Fatal(err) }
  client, err := smtp.NewClient(conn, "relay.test"); if err != nil { conn.Close(); t.Fatal(err) }
  err = requireRelayPlainAuth(client)
  if (err == nil) != tc.allowed { t.Errorf("allowed=%t, error=%v", tc.allowed, err) }
  _ = client.Close()
  select { case peerErr := <-done: if peerErr != nil { t.Fatal(peerErr) }; case <-time.After(4*time.Second): t.Fatal("SMTP peer stuck") }
 }) }
}
func TestRequireRelayPlainAuthNilClient(t *testing.T) { if err := requireRelayPlainAuth(nil); err == nil { t.Fatal("nil client accepted") } }
