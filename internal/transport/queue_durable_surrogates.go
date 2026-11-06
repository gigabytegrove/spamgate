package transport

import (
 "errors"
 "strconv"
)

// validateDurableJSONSurrogates rejects unpaired UTF-16 escape sequences.
// encoding/json otherwise replaces these with U+FFFD during recovery,
// silently changing persisted evidence even when the JSON bytes are UTF-8.
func validateDurableJSONSurrogates(data []byte) error {
 inString := false
 for i := 0; i < len(data); i++ {
  switch data[i] {
  case '"':
   inString = !inString
  case '\\':
   if !inString { continue }
   if i+1 >= len(data) { return errors.New("truncated durable JSON escape") }
   if data[i+1] != 'u' { i++; continue }
   first, ok := durableHexQuad(data, i+2)
   if !ok { return errors.New("invalid durable JSON Unicode escape") }
   i += 5
   if first >= 0xDC00 && first <= 0xDFFF {
    return errors.New("unpaired low surrogate in durable JSON")
   }
   if first >= 0xD800 && first <= 0xDBFF {
    if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
     return errors.New("unpaired high surrogate in durable JSON")
    }
    second, ok := durableHexQuad(data, i+3)
    if !ok || second < 0xDC00 || second > 0xDFFF {
     return errors.New("invalid durable JSON surrogate pair")
    }
    i += 6
   }
  }
 }
 return nil
}

func durableHexQuad(data []byte, start int) (uint16, bool) {
 if start+4 > len(data) { return 0, false }
 n, err := strconv.ParseUint(string(data[start:start+4]), 16, 16)
 return uint16(n), err == nil
}
