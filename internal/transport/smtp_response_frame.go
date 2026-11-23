package transport

import (
 "errors"
 "fmt"
 "strings"
)

// validateSMTPResponseFrame validates an entire SMTP reply before the first
// network write. It deliberately rejects ambiguous framing and control bytes.
func validateSMTPResponseFrame(frame string) error {
 if len(frame) < 6 || len(frame) > 16384 || !strings.HasSuffix(frame, "\r\n") {
  return errors.New("SMTP response must be CRLF terminated and within 16 KiB")
 }
 lines := strings.Split(strings.TrimSuffix(frame, "\r\n"), "\r\n")
 if len(lines) > 100 { return errors.New("too many SMTP response lines") }
 var code string
 for i, line := range lines {
  if len(line) < 4 || len(line)+2 > 512 { return fmt.Errorf("invalid SMTP response line %d length", i+1) }
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
  // RFC 3463 enhanced status codes must agree with the basic SMTP reply
  // class. A mismatched class can cause clients to interpret a temporary
  // failure as permanent, or vice versa.
  if len(line) >= 6 && line[4] >= '2' && line[4] <= '5' && line[5] == '.' {
   if line[4] != line[0] { return errors.New("enhanced SMTP status class differs from reply code") }
   end := strings.IndexByte(line[4:], ' ')
   token := line[4:]
   if end >= 0 { token = line[4:4+end] }
   parts := strings.Split(token, ".")
   if len(parts) != 3 || len(parts[0]) != 1 || len(parts[1]) == 0 || len(parts[2]) == 0 || len(parts[1]) > 3 || len(parts[2]) > 3 {
    return errors.New("malformed enhanced SMTP status")
   }
   for _, part := range parts {
    for j := 0; j < len(part); j++ {
     if part[j] < '0' || part[j] > '9' { return errors.New("malformed enhanced SMTP status") }
    }
   }
  }
 }
 return nil
}
