package transport

import (
 "bytes"
 "encoding/json"
 "errors"
 "strings"
 "unicode/utf8"
)

// validateCanonicalSpoolRecordJSON runs before decoding persisted originals.
// encoding/json accepts case-insensitive struct keys and decodes null string
// array elements to "". Neither behavior is safe for SMTP recipient identity.
// Unknown extension keys are retained for forward-compatible spool upgrades.
func validateCanonicalSpoolRecordJSON(data []byte) error {
 // encoding/json silently replaces malformed UTF-8 with U+FFFD. A durable
 // SMTP original must never acquire a different identity during recovery.
 if !utf8.Valid(data) { return errors.New("invalid UTF-8 in durable spool JSON") }
 if err := validateDurableJSONSurrogates(data); err != nil { return err }
 if err := validateUniqueDurableJSON(data); err != nil { return err }
 var fields map[string]json.RawMessage
 if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
  return errors.New("invalid durable spool JSON object")
 }
 canonical := [...]string{
  "id", "sender", "recipients", "subject", "created", "next_attempt",
  "updated", "attempts", "state", "last_error", "size", "delivered_at",
  "raw", "integrity_sha256", "state_sha256", "scan",
 }
 for key := range fields {
  for _, name := range canonical {
   if key != name && strings.EqualFold(key, name) {
    return errors.New("noncanonical durable spool field alias")
   }
  }
 }
 for _, name := range [...]string{"id", "sender", "recipients", "raw", "state", "size", "attempts", "created", "updated", "next_attempt"} {
  value, ok := fields[name]
  if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
   return errors.New("missing or null durable spool identity field")
  }
 }
 for _, name := range [...]string{"id", "sender", "state"} {
  var value string
  if err := json.Unmarshal(fields[name], &value); err != nil {
   return errors.New("invalid durable spool identity field type")
  }
 }
 if err := validateDurableLifecycleFields(fields); err != nil { return err }
 // Persisted legacy records may lack integrity digests. They must still obey
 // the same SMTP envelope safety boundary as newly admitted mail. Validate
 // decoded values rather than raw JSON bytes so escaped controls cannot pass.
 var sender string
 if err := json.Unmarshal(fields["sender"], &sender); err != nil {
  return errors.New("invalid durable spool sender")
 }
 var raw string
 if err := json.Unmarshal(fields["raw"], &raw); err != nil {
  return errors.New("invalid durable spool raw message encoding")
 }
 var size json.Number
 decoder := json.NewDecoder(bytes.NewReader(fields["size"]))
 decoder.UseNumber()
 if err := decoder.Decode(&size); err != nil {
  return errors.New("invalid durable spool size type")
 }
 if _, err := size.Int64(); err != nil {
  return errors.New("invalid durable spool integer size")
 }
 var recipients []json.RawMessage
 if err := json.Unmarshal(fields["recipients"], &recipients); err != nil || len(recipients) == 0 {
  return errors.New("invalid durable spool recipient array")
 }
 decodedRecipients := make([]string, 0, len(recipients))
 for _, element := range recipients {
  if len(element) == 0 || element[0] != '"' {
   return errors.New("invalid durable spool recipient element type")
  }
  var recipient string
  if err := json.Unmarshal(element, &recipient); err != nil || recipient == "" {
   return errors.New("invalid durable spool recipient value")
  }
  decodedRecipients = append(decodedRecipients, recipient)
 }
 if err := validateIntakeEnvelope(sender, decodedRecipients); err != nil {
  // Do not include private envelope values in durable audit errors.
  return errors.New("unsafe durable SMTP envelope")
 }
 return nil
}
