package smtpprobe

import (
 "bufio"
 "context"
 "errors"
 "net"
 "strings"
 "testing"
 "time"
)

// A real socket exercises the greeting timing branch, including the error
// path that previously contained a missing statement separator.
func TestGreetingLatencyAndRejectionClassification(t *testing.T) {
 ln, err := net.Listen("tcp", "127.0.0.1:0")
 if err != nil { t.Fatal(err) }
 defer ln.Close()
 done := make(chan error, 1)
 go func() {
  conn, err := ln.Accept()
  if err != nil { done <- err; return }
  defer conn.Close()
  time.Sleep(12 * time.Millisecond)
  _, err = conn.Write([]byte("421 service temporarily unavailable\r\n"))
  done <- err
 }()
 result, err := Probe(context.Background(), Options{Address:ln.Addr().String(), Timeout:time.Second})
 var reply *SMTPReplyError
 if !errors.As(err, &reply) || reply.Code != 421 || reply.Stage != "greeting" {
  t.Fatalf("expected typed 421 greeting rejection, got result=%+v error=%v",result,err)
 }
 if result.GreetingDurationMillis < 1 || result.ProbeDurationMillis < result.GreetingDurationMillis {
  t.Fatalf("missing greeting timing evidence: %+v",result)
 }
 if result.FailureStage != "greeting" || result.FailureKind != "SMTP_TEMPORARY_REJECTION" {
  t.Fatalf("incorrect rejection classification: %+v",result)
 }
 if result.EHLORoundTripMillis != 0 || result.StartTLSRoundTripMillis != 0 {
  t.Fatalf("unattempted stages have timing: %+v",result)
 }
 select { case err := <-done: if err != nil { t.Fatal(err) }; case <-time.After(time.Second): t.Fatal("server goroutine stuck") }
}

func TestReplyParserRejectsAmbiguousOrOversizedFrames(t *testing.T) {
 tests := []struct{name, wire string}{
  {"bare LF","220 ready\n"},
  {"mixed reply codes","250-first\r\n251 second\r\n"},
  {"control byte","220 hi\x00there\r\n"},
  {"overlong line","220 "+strings.Repeat("x",maxLine)+"\r\n"},
  {"unterminated multiline","250-hello\r\n"},
 }
 for _,tc := range tests {
  t.Run(tc.name,func(t *testing.T){
   _,_,err:=readReply(bufio.NewReader(strings.NewReader(tc.wire)))
   if err==nil { t.Fatalf("accepted malformed SMTP reply %q",tc.name) }
  })
 }
}
