package transport

import (
 "strings"
 "testing"
)

// RFC 5321 limits a reply line to 512 octets INCLUDING CRLF.
func TestSMTPResponseWireLineLimit(t *testing.T) {
 for _, tc := range []struct{name string; size int; valid bool}{
  {"exactly_512", 506, true},
  {"513_octets", 507, false},
  {"short", 1, true},
 } {
  t.Run(tc.name, func(t *testing.T) {
   frame := "250 " + strings.Repeat("X", tc.size) + "\r\n"
   err := validateSMTPResponseFrame(frame)
   if (err == nil) != tc.valid { t.Fatalf("size=%d valid=%v error=%v",len(frame),tc.valid,err) }
  })
 }
}

func TestSMTPEnhancedStatusNumericBoundaries(t *testing.T) {
 cases := []struct{frame string; valid bool}{
  {"550 5.7.1 rejected\r\n",true},
  {"550 5.999.999 rejected\r\n",true},
  {"550 5.1000.1 rejected\r\n",false},
  {"550 5.7.1000 rejected\r\n",false},
  {"550 5.7.1.2 rejected\r\n",false},
  {"550 5.7. rejected\r\n",false},
 }
 for _, tc := range cases {
  err := validateSMTPResponseFrame(tc.frame)
  if (err==nil)!=tc.valid {t.Errorf("%q valid=%v err=%v",tc.frame,tc.valid,err)}
 }
}
