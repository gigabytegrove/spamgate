package transport

import "testing"

func TestSMTPResponseEnhancedStatusConsistency(t *testing.T) {
 valid := []string{
  "250 2.0.0 accepted\r\n",
  "421 4.4.2 command timeout\r\n",
  "550 5.7.1 rejected\r\n",
  "250-PIPELINING\r\n250 SIZE 10485760\r\n",
  "250 "+string(make([]byte, 0))+"OK\r\n",
 }
 for _, s := range valid {
  if err := validateSMTPResponseFrame(s); err != nil { t.Errorf("valid %q: %v", s, err) }
 }
 invalid := []string{
  "250 5.7.1 misleading success\r\n",
  "550 4.4.2 misleading permanent failure\r\n",
  "421 4.4 malformed\r\n",
  "550 5.7.X invalid\r\n",
  "550 5..1 invalid\r\n",
  "250 "+repeatSMTPResponseByte('X', 509)+"\r\n",
 }
 for _, s := range invalid {
  if err := validateSMTPResponseFrame(s); err == nil { t.Errorf("accepted %q", s) }
 }
}

func repeatSMTPResponseByte(b byte, n int) string {
 buf := make([]byte, n)
 for i := range buf { buf[i] = b }
 return string(buf)
}
