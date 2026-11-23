package transport

import "testing"

func TestSMTPResponseEnhancedBoundary(t *testing.T) {
 cases := []struct {
  name, frame string
  valid bool
 }{
  {"normal", "250 2.0.0 Queued\r\n", true},
  {"plain prose", "250 SpamGate ready\r\n", true},
  {"multiline", "250-SpamGate\r\n250 SIZE 10485760\r\n", true},
  {"valid max components", "550 5.999.999 Failure\r\n", true},
  {"class mismatch", "450 5.1.1 Failure\r\n", false},
  {"missing component", "550 5.1 Failure\r\n", false},
  {"empty component", "550 5..1 Failure\r\n", false},
  {"oversized component", "550 5.1234.1 Failure\r\n", false},
  {"non numeric component", "550 5.1.x Failure\r\n", false},
  {"trailing dot", "550 5.1. Failure\r\n", false},
  {"unframed newline", "250 Good\n550 Bad\r\n", false},
  {"mixed codes", "250-First\r\n550 Last\r\n", false},
  {"exact 512", "250 "+repeatSMTPReplyByte('a', 506)+"\r\n", true},
  {"513", "250 "+repeatSMTPReplyByte('a', 507)+"\r\n", false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   err := validateSMTPResponseFrame(tc.frame)
   if (err == nil) != tc.valid { t.Fatalf("valid=%v err=%v", tc.valid, err) }
  })
 }
}
func repeatSMTPReplyByte(b byte, n int) string {
 out := make([]byte, n)
 for i := range out { out[i] = b }
 return string(out)
}
