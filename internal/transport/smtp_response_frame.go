package transport

import (
 "errors"
 "fmt"
 "strings"
)

// validateSMTPResponseFrame checks the complete response before any bytes are sent.
// RFC 5321 limits each line, including CRLF, to 512 octets.
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
   if line[j] < 0x20 || line[j] > 0x7e { return fmt.Errorf("nonprintable SMTP response byte on line %d", i+1) }
  }
  for j := 0; j < 3; j++ {
   if line[j] < '0' || line[j] > '9' { return errors.New("non-numeric SMTP response code") }
  }
  if line[0] < '2' || line[0] > '5' { return errors.New("unsupported SMTP response code") }
  if code == "" { code = line[:3] } else if code != line[:3] { return errors.New("inconsistent multiline SMTP response code") }
  separator := byte('-')
  if i == len(lines)-1 { separator = ' ' }
  if line[3] != separator { return errors.New("invalid multiline SMTP response separator") }
  if err := validateSMTPEnhancedReply(line[0], line[4:]); err != nil {
   return fmt.Errorf("SMTP response line %d: %w", i+1, err)
  }
 }
 return nil
}

// validateSMTPEnhancedReply rejects malformed enhanced codes instead of treating
// a malformed candidate as unstructured text. An enhanced code starts with a
// class digit and a dot; non-code prose remains permitted.
func validateSMTPEnhancedReply(primary byte, text string) error {
 if len(text) < 2 || text[0] < '2' || text[0] > '5' || text[1] != '.' {
  return nil
 }
 end := strings.IndexByte(text, ' ')
 if end < 0 { end = len(text) }
 token := text[:end]
 parts := strings.Split(token, ".")
 if len(parts) != 3 || len(parts[0]) != 1 || len(parts[1]) < 1 || len(parts[1]) > 3 || len(parts[2]) < 1 || len(parts[2]) > 3 {
  return errors.New("malformed enhanced SMTP status")
 }
 if parts[0][0] != primary { return errors.New("enhanced SMTP status class differs from reply code") }
 for _, part := range parts {
  for j := 0; j < len(part); j++ {
   if part[j] < '0' || part[j] > '9' { return errors.New("malformed enhanced SMTP status") }
  }
 }
 return nil
}
