package spoolaudit

import (
 "encoding/json"
 "errors"
 "strings"
)

// validateDurableCanonicalKeys rejects case-folded aliases of serialized
// spoolRecord fields. encoding/json accepts case-insensitive struct keys and
// later aliases can overwrite previously validated canonical values. Unknown
// extension fields remain permitted for forward compatibility.
func validateDurableCanonicalKeys(data []byte) error {
 var fields map[string]json.RawMessage
 if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
  return errors.New("invalid durable envelope JSON object")
 }
 for key := range fields {
  for _, canonical := range durableRecordJSONKeys {
   if key != canonical && strings.EqualFold(key, canonical) {
    return errors.New("durable envelope noncanonical field alias")
   }
  }
 }
 return nil
}

// Keep synchronized with record's JSON tags in audit.go. Do not silently
// accept alternate spellings of security-sensitive or diagnostic fields.
var durableRecordJSONKeys = [...]string{
 "id", "sender", "recipients", "subject", "created", "next_attempt",
 "updated", "attempts", "state", "last_error", "size", "delivered_at",
 "raw", "integrity_sha256", "state_sha256", "scan",
}
