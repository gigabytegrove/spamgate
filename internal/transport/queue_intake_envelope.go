package transport

import "errors"

// validateIntakeEnvelope rejects raw ASCII control characters in SMTP
// envelope arguments before a record can enter the durable queue. SMTPUTF8
// addresses remain valid; only ASCII control bytes and DEL are prohibited.
// An empty reverse path is valid for delivery status notifications.
func validateIntakeEnvelope(sender string, recipients []string) error {
 if containsSMTPControl(sender) {
  return errors.New("SMTP sender contains prohibited control bytes")
 }
 if len(recipients) == 0 || len(recipients) > 1000 {
  return errors.New("invalid SMTP recipient count")
 }
 for _, recipient := range recipients {
  if recipient == "" || containsSMTPControl(recipient) {
   return errors.New("SMTP recipient is empty or contains prohibited control bytes")
  }
 }
 return nil
}

// containsSMTPControl operates on raw bytes, preserving UTF-8 and never
// echoing attacker-supplied addresses into diagnostic errors.
func containsSMTPControl(value string) bool {
 for i := 0; i < len(value); i++ {
  if value[i] < 0x20 || value[i] == 0x7f {
   return true
  }
 }
 return false
}
