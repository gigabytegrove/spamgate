package transport

import (
 "errors"
 "unicode"
 "unicode/utf8"
)

// validateIntakeEnvelope rejects unsafe SMTP envelope text before durable
// admission. The empty reverse path is valid for delivery status notifications.
// Valid SMTPUTF8 letters and marks remain supported.
func validateIntakeEnvelope(sender string, recipients []string) error {
 if !validSMTPEnvelopeText(sender) {
  return errors.New("SMTP sender contains invalid UTF-8 or prohibited control characters")
 }
 if len(recipients) == 0 || len(recipients) > 1000 {
  return errors.New("invalid SMTP recipient count")
 }
 for _, recipient := range recipients {
  if recipient == "" || !validSMTPEnvelopeText(recipient) {
   return errors.New("SMTP recipient is empty, contains invalid UTF-8, or prohibited control characters")
  }
 }
 return nil
}

// validSMTPEnvelopeText rejects ASCII and non-ASCII controls, Unicode line
// separators and bidirectional formatting controls. These code points can
// cause downstream log, header or SMTP command confusion even though the UTF-8
// byte sequence itself is well formed. Error messages never echo addresses.
func validSMTPEnvelopeText(value string) bool {
 if !utf8.ValidString(value) {
  return false
 }
 for _, r := range value {
  if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
   return false
  }
  // Direction overrides/isolates and directional marks are invisible
  // formatting controls; do not allow them to disguise mailbox identity.
  if r == 0x061c || r == 0x200e || r == 0x200f ||
   (r >= 0x202a && r <= 0x202e) ||
   (r >= 0x2066 && r <= 0x2069) {
   return false
  }
 }
 return true
}
