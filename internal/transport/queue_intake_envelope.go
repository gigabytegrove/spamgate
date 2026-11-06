package transport

import (
 "errors"
 "unicode"
 "unicode/utf8"
)

// SMTP paths have much smaller RFC limits. These generous ceilings protect
// the native spool from unbounded envelope metadata without rejecting common
// SMTPUTF8 deployments or assuming that callers have stripped path brackets.
const (
 maxEnvelopeAddressBytes = 512
 maxEnvelopeRecipientsBytes = 64 << 10
)

// validateIntakeEnvelope rejects unsafe SMTP envelope text before durable
// admission. Empty reverse paths remain valid for delivery-status notifications.
func validateIntakeEnvelope(sender string, recipients []string) error {
 if len(sender) > maxEnvelopeAddressBytes || !validSMTPEnvelopeText(sender) {
  return errors.New("SMTP sender is oversized or contains invalid UTF-8 or prohibited control characters")
 }
 if len(recipients) == 0 || len(recipients) > 1000 {
  return errors.New("invalid SMTP recipient count")
 }
 total := 0
 for _, recipient := range recipients {
  if recipient == "" || len(recipient) > maxEnvelopeAddressBytes || !validSMTPEnvelopeText(recipient) {
   return errors.New("SMTP recipient is empty, oversized, contains invalid UTF-8, or prohibited control characters")
  }
  // Check before addition to keep the aggregate bound explicit and safe.
  if len(recipient) > maxEnvelopeRecipientsBytes-total {
   return errors.New("SMTP recipient envelope exceeds aggregate size limit")
  }
  total += len(recipient)
 }
 return nil
}

// validSMTPEnvelopeText rejects ASCII and non-ASCII controls, Unicode line
// separators and format controls. Errors never echo private addresses.
func validSMTPEnvelopeText(value string) bool {
 if !utf8.ValidString(value) { return false }
 for _, r := range value {
  if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || unicode.Is(unicode.Cf, r) { return false }
 }
 return true
}
