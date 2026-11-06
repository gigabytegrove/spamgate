package transport

import (
 "bytes"
 "encoding/json"
 "errors"
 "io"
)

// validateUniqueDurableJSON rejects ambiguous JSON object members at any depth.
// encoding/json otherwise silently uses the last occurrence of a key, which
// can change persisted recipient, scan or delivery evidence on recovery.
func validateUniqueDurableJSON(data []byte) error {
 decoder := json.NewDecoder(bytes.NewReader(data))
 if err := walkUniqueDurableJSON(decoder, 0); err != nil { return err }
 if _, err := decoder.Token(); err != io.EOF { return errors.New("trailing durable JSON content") }
 return nil
}

const maxDurableJSONDepth = 64

func walkUniqueDurableJSON(decoder *json.Decoder, depth int) error {
 if depth > maxDurableJSONDepth { return errors.New("durable JSON nesting limit exceeded") }
 token, err := decoder.Token()
 if err != nil { return errors.New("invalid durable JSON token") }
 delimiter, ok := token.(json.Delim)
 if !ok { return nil }
 switch delimiter {
 case '{':
  seen := make(map[string]struct{})
  for decoder.More() {
   keyToken, err := decoder.Token()
   if err != nil { return errors.New("invalid durable JSON object key") }
   key, ok := keyToken.(string)
   if !ok { return errors.New("invalid durable JSON object key") }
   if _, duplicate := seen[key]; duplicate { return errors.New("duplicate durable JSON object key") }
   seen[key] = struct{}{}
   if err := walkUniqueDurableJSON(decoder, depth+1); err != nil { return err }
  }
  end, err := decoder.Token()
  if err != nil || end != json.Delim('}') { return errors.New("invalid durable JSON object terminator") }
 case '[':
  for decoder.More() {
   if err := walkUniqueDurableJSON(decoder, depth+1); err != nil { return err }
  }
  end, err := decoder.Token()
  if err != nil || end != json.Delim(']') { return errors.New("invalid durable JSON array terminator") }
 default:
  return errors.New("unexpected durable JSON delimiter")
 }
 return nil
}
