package transport

import (
 "encoding/json"
 "errors"
)

// validateDurableLifecycleFields refuses zero-valued state invented by Go's
// permissive decoder. This runs on both published and crash-retained originals.
func validateDurableLifecycleFields(fields map[string]json.RawMessage) error {
 attempts, err := strictDurableNonnegativeInteger(fields["attempts"])
 // Legacy records may exceed the current retry ceiling; recovery must park
 // them without another send, rather than refusing startup. Reject corruption.
 if err != nil || attempts > 1000000 {
  return errors.New("invalid durable delivery attempt count")
 }
 for _, key := range [...]string{"created", "updated", "next_attempt"} {
  if _, err := parseDurableTimestamp(fields[key], false); err != nil {
   return errors.New("invalid durable delivery timestamp")
  }
 }
 if raw, ok := fields["delivered_at"]; ok {
  if _, err := parseDurableTimestamp(raw, true); err != nil {
   return errors.New("invalid durable delivered timestamp")
  }
 }
 return nil
}
