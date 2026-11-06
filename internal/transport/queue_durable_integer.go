package transport

import (
 "errors"
 "strconv"
)

// strictDurableNonnegativeInteger accepts only a canonical, unquoted JSON
// integer in the signed 64-bit range. Persisted queue metadata must not
// change type or meaning during encoding/json's permissive decoding.
func strictDurableNonnegativeInteger(raw []byte) (int64, error) {
 // Bound corrupted numeric tokens before scanning or converting them. A signed\n // 64-bit nonnegative integer cannot exceed 19 decimal digits.\n if len(raw) > 19 {\n  return 0, errors.New("durable integer exceeds signed range")\n }\n if len(raw) == 0 || raw[0] < '0' || raw[0] > '9' {
  return 0, errors.New("invalid durable nonnegative integer")
 }
 if len(raw) > 1 && raw[0] == '0' {
  return 0, errors.New("noncanonical durable integer")
 }
 for _, b := range raw {
  if b < '0' || b > '9' {
   return 0, errors.New("invalid durable integer syntax")
  }
 }
 value, err := strconv.ParseInt(string(raw), 10, 64)
 if err != nil {
  return 0, errors.New("durable integer exceeds signed range")
 }
 return value, nil
}
