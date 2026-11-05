package transport

import (
 "bytes"
 "encoding/json"
 "errors"
 "strings"
)

// validateCanonicalSpoolRecordJSON runs before decoding persisted originals.
// encoding/json accepts case-insensitive struct keys and decodes null string
// array elements to "". Neither behavior is safe for SMTP recipient identity.
// Unknown extension keys are retained for forward-compatible spool upgrades.
func validateCanonicalSpoolRecordJSON(data []byte) error {
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
 for _, name := range [...]string{"id", "sender", "recipients", "raw", "state", "size"} {
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
 for _, element := range recipients {
  if len(element) == 0 || element[0] != '"' {
   return errors.New("invalid durable spool recipient element type")
  }
  var recipient string
  if err := json.Unmarshal(element, &recipient); err != nil || recipient == "" {
   return errors.New("invalid durable spool recipient value")
  }
 }
 return nil
}
