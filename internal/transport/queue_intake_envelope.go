package transport

import (
 "errors"
 "strings"
)

// validateIntakeEnvelope rejects values that cannot be represented safely as
// SMTP envelope arguments. The empty reverse path is legal for DSNs, but
// an empty recipient is never a deliverable address. Do not normalize here:
// the persisted envelope must be the exact one accepted at intake.
func validateIntakeEnvelope(sender string, recipients []string) error {
 if strings.ContainsAny(sender, "\r\n\x00") {
  return errors.New("SMTP sender contains prohibited control bytes")
 }
 if len(recipients) == 0 || len(recipients) > 1000 {
  return errors.New("invalid SMTP recipient count")
 }
 for _, recipient := range recipients {
  if recipient == "" || strings.ContainsAny(recipient, "\r\n\x00") {
   return errors.New("SMTP recipient is empty or contains prohibited control bytes")
  }
 }
 return nil
}
