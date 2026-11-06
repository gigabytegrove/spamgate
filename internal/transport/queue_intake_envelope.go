package transport

import (
 "errors"
 "unicode/utf8"
)

// validateIntakeEnvelope rejects malformed UTF-8 and raw ASCII controls
// before durable queue admission. SMTPUTF8 addresses remain supported and
// an empty reverse path remains valid for delivery status notifications.
func validateIntakeEnvelope(sender string, recipients []string) error {
 if !validSMTPEnvelopeText(sender) {
  return errors.New("SMTP sender contains invalid UTF-8 or prohibited control bytes")
 }
 if len(recipients) == 0 || len(recipients) > 1000 {
  return errors.New("invalid SMTP recipient count")
 }
 for _, recipient := range recipients {
  if recipient == "" || !validSMTPEnvelopeText(recipient) {
   return errors.New("SMTP recipient is empty, contains invalid UTF-8, or prohibited control bytes")
  }
 }
 return nil
}

// validSMTPEnvelopeText checks byte validity without echoing private address
// contents into errors. UTF-8 validation rejects malformed, overlong and
// surrogate encodings that downstream SMTP implementations may interpret
// inconsistently.
func validSMTPEnvelopeText(value string) bool {
 if !utf8.ValidString(value) {
  return false
 }
 for i := 0; i < len(value); i++ {
  if value[i] < 0x20 || value[i] == 0x7f {
   return false
  }
 }
 return true
}
