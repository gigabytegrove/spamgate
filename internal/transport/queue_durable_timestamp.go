package transport

import (
 "bytes"
 "encoding/json"
 "errors"
 "time"
)

// parseDurableTimestamp validates the JSON type and rejects timestamps that
// decode to Go's zero time. Never include private persisted values in errors.
func parseDurableTimestamp(raw json.RawMessage, allowEmpty bool) (time.Time, error) {
 value := bytes.TrimSpace(raw)
 if len(value) == 0 || value[0] != '"' {
  return time.Time{}, errors.New("invalid durable delivery timestamp type")
 }
 var stamp string
 if err := json.Unmarshal(value, &stamp); err != nil {
  return time.Time{}, errors.New("invalid durable delivery timestamp encoding")
 }
 if stamp == "" && allowEmpty {
  return time.Time{}, nil
 }
 parsed, err := time.Parse(time.RFC3339Nano, stamp)
 if err != nil || parsed.IsZero() {
  return time.Time{}, errors.New("invalid durable delivery timestamp value")
 }
 return parsed, nil
}
