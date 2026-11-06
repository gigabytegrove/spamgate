package transport

import (
 "bytes"
 "encoding/json"
 "errors"
 "strings"
 "time"
)

// parseDurableTimestamp validates persisted timestamp types without including
// private record values in diagnostics. Optional zero values are retained for
// compatibility with Go's time.Time JSON serialization.
func parseDurableTimestamp(raw json.RawMessage, allowEmpty bool) (time.Time, error) {
 value := bytes.TrimSpace(raw)
 if len(value) == 0 || value[0] != '"' {
  return time.Time{}, errors.New("invalid durable delivery timestamp type")
 }
 var stamp string
 if err := json.Unmarshal(value, &stamp); err != nil {
  return time.Time{}, errors.New("invalid durable delivery timestamp encoding")
 }
 if allowEmpty && (stamp == "" || stamp == "0001-01-01T00:00:00Z") {
  return time.Time{}, nil
 }
 // Go's RFC3339 parser accepts fractional seconds beyond nanosecond
 // precision and silently truncates them. Persisted scheduling evidence must
 // not change during recovery. Accept at most nine fractional digits.
 if !durableTimestampPrecisionValid(stamp) {
  return time.Time{}, errors.New("invalid durable delivery timestamp precision")
 }
 parsed, err := time.Parse(time.RFC3339Nano, stamp)
 if err != nil || parsed.IsZero() {
  return time.Time{}, errors.New("invalid durable delivery timestamp value")
 }
 return parsed, nil
}

func durableTimestampPrecisionValid(stamp string) bool {
 // RFC3339 dates cannot contain a dot; a dot in the time portion begins
 // fractional seconds and must be followed by 1..9 ASCII digits.
 dot := strings.IndexByte(stamp, '.')
 if dot < 0 { return true }
 digits := 0
 for i := dot + 1; i < len(stamp); i++ {
  if stamp[i] < '0' || stamp[i] > '9' { break }
  digits++
  if digits > 9 { return false }
 }
 return digits > 0
}
