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
 created, err := parseDurableTimestamp(fields["created"], false)
 if err != nil {
  return errors.New("invalid durable created timestamp")
 }
 updated, err := parseDurableTimestamp(fields["updated"], false)
 if err != nil {
  return errors.New("invalid durable updated timestamp")
 }
 if updated.Before(created) {
  return errors.New("durable update precedes creation")
 }
 if _, err := parseDurableTimestamp(fields["next_attempt"], false); err != nil {
  return errors.New("invalid durable next attempt timestamp")
 }
 if raw, ok := fields["delivered_at"]; ok {
  delivered, err := parseDurableTimestamp(raw, true)
  if err != nil {
   return errors.New("invalid durable delivered timestamp")
  }
  if !delivered.IsZero() && delivered.Before(created) {
   return errors.New("durable delivery precedes creation")
  }
 }
 return nil
}
