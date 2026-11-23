package transport

import (
 "bufio"
 "net"
 "strings"
 "testing"
 "time"
)

func TestSMTPResponseFrameValidation(t *testing.T) {
 valid := []string{
  "220 SpamGate ESMTP filtering gateway ready\r\n",
  "421 4.4.2 SMTP command timeout\r\n",
  "250-SpamGate\r\n250-XFORWARD ADDR\r\n250-8BITMIME\r\n250 SIZE 10485760\r\n",
  "554 5.7.1 Client network not trusted\r\n",
 }
 for _, frame := range valid { if err := validateSMTPResponseFrame(frame); err != nil { t.Errorf("valid %q: %v", frame, err) } }
 invalid := []string{
  "", "250 OK", "250 OK\n", "250 OK\r\n250 INJECT\r\n",
  "250-First\r\n550 Second\r\n", "250-First\r\n",
  "250 OK\r\n\r\n", "250 OK\r\nMAIL FROM:<x@y>\r\n",
  "250 OK\x00\r\n", "250 OK\t\r\n", "250 OK\rX\r\n",
  "999 OK\r\n", "2500 OK\r\n", "2A0 OK\r\n",
  "250 "+strings.Repeat("X", 1000)+"\r\n",
  strings.Repeat("250-OK\r\n", 101)+"250 OK\r\n",
 }
 for _, frame := range invalid { if err := validateSMTPResponseFrame(frame); err == nil { t.Errorf("accepted invalid frame %q", frame) } }
}

func TestSMTPResponseRejectsInjectionWithoutWriting(t *testing.T) {
 server, peer := net.Pipe()
 defer server.Close()
 defer peer.Close()
 if err := smtpWriteResponse(server, bufio.NewWriter(server), "250 OK\r\n550 forged\r\n"); err == nil {
  t.Fatal("injected reply accepted")
 }
 if err := peer.SetReadDeadline(time.Now().Add(20*time.Millisecond)); err != nil { t.Fatal(err) }
 b := make([]byte, 1)
 if n, err := peer.Read(b); n != 0 || err == nil { t.Fatalf("unexpected socket bytes: %d %v", n, err) }
}
