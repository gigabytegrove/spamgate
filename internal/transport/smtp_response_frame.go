package transport

import (
 "errors"
 "fmt"
 "strings"
)

// validateSMTPResponseFrame rejects ambiguous or injectable SMTP replies
// before any bytes are written to the network. Multiline replies must use
// the same three-digit code and terminate with a space separator.
func validateSMTPResponseFrame(frame string) error {
 if len(frame) < 6 || len(frame) > 16384 || !strings.HasSuffix(frame, "\r\n") {
  return errors.New("SMTP response must be CRLF terminated and within 16 KiB")
 }
 lines := strings.Split(strings.TrimSuffix(frame, "\r\n"), "\r\n")
 if len(lines) > 100 { return errors.New("too many SMTP response lines") }
 var code string
 for i, line := range lines {
  if len(line) < 4 || len(line) > 1000 { return fmt.Errorf("invalid SMTP response line %d length", i+1) }
  for j := 0; j < len(line); j++ {
   b := line[j]
   if b < 0x20 || b > 0x7e { return fmt.Errorf("nonprintable SMTP response byte on line %d", i+1) }
  }
  for j := 0; j < 3; j++ {
   if line[j] < '0' || line[j] > '9' { return errors.New("non-numeric SMTP response code") }
  }
  if line[0] < '2' || line[0] > '5' { return errors.New("unsupported SMTP response code") }
  if code == "" { code = line[:3] } else if code != line[:3] { return errors.New("inconsistent multiline SMTP response code") }
  separator := byte('-')
  if i == len(lines)-1 { separator = ' ' }
  if line[3] != separator { return errors.New("invalid multiline SMTP response separator") }
 }
 return nil
}
