package transport

import (
 "errors"
 "fmt"
 "testing"
)

func TestSMTPDataReadFailureReply(t *testing.T) {
 cases := []struct {
  name string
  err error
  code int
  message string
 }{
  {"oversize", errSMTPDataTooLarge, 552, "5.3.4 Message too large"},
  {"wrapped oversize", fmt.Errorf("DATA: %w", errSMTPDataTooLarge), 552, "5.3.4 Message too large"},
  {"framing", errors.New("missing CRLF terminator"), 554, "5.6.0 Invalid SMTP DATA framing"},
  {"transport", errors.New("unexpected EOF"), 554, "5.6.0 Invalid SMTP DATA framing"},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   code, message := smtpDataReadFailureReply(tc.err)
   if code != tc.code || message != tc.message {
    t.Fatalf("reply = %d %q; want %d %q", code, message, tc.code, tc.message)
   }
  })
 }
}
