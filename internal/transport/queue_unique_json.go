package transport

import (
 "bytes"
 "encoding/json"
 "errors"
 "io"
)

// Bound the structural recovery pass so a corrupt persisted record cannot
// consume disproportionate CPU or memory through tiny JSON tokens and keys.
const (
 maxDurableJSONDepth = 64
 maxDurableJSONTokens = 100000
 maxDurableJSONObjectKeys = 8192
 maxDurableJSONKeyBytes = 4096
)

func validateUniqueDurableJSON(data []byte) error {
 decoder := json.NewDecoder(bytes.NewReader(data))
 budget := maxDurableJSONTokens
 if err := walkUniqueDurableJSONBounded(decoder, 0, &budget); err != nil { return err }
 if _, err := decoder.Token(); err != io.EOF { return errors.New("trailing durable JSON content") }
 return nil
}

// Retain the original internal entry point for existing callers.
func walkUniqueDurableJSON(decoder *json.Decoder, depth int) error {
 budget := maxDurableJSONTokens
 return walkUniqueDurableJSONBounded(decoder, depth, &budget)
}

func walkUniqueDurableJSONBounded(decoder *json.Decoder, depth int, budget *int) error {
 if depth > maxDurableJSONDepth { return errors.New("durable JSON nesting limit exceeded") }
 if *budget <= 0 { return errors.New("durable JSON token budget exceeded") }
 *budget--
 token, err := decoder.Token()
 if err != nil { return errors.New("invalid durable JSON token") }
 delimiter, ok := token.(json.Delim)
 if !ok { return nil }
 switch delimiter {
 case '{':
  seen := make(map[string]struct{})
  for decoder.More() {
   if len(seen) >= maxDurableJSONObjectKeys { return errors.New("durable JSON object key limit exceeded") }
   if *budget <= 0 { return errors.New("durable JSON token budget exceeded") }
   *budget--
   keyToken, err := decoder.Token()
   if err != nil { return errors.New("invalid durable JSON object key") }
   key, ok := keyToken.(string)
   if !ok { return errors.New("invalid durable JSON object key") }
   if len(key) > maxDurableJSONKeyBytes { return errors.New("durable JSON object key too long") }
   if _, duplicate := seen[key]; duplicate { return errors.New("duplicate durable JSON object key") }
   seen[key] = struct{}{}
   if err := walkUniqueDurableJSONBounded(decoder, depth+1, budget); err != nil { return err }
  }
  if *budget <= 0 { return errors.New("durable JSON token budget exceeded") }
  *budget--
  end, err := decoder.Token()
  if err != nil || end != json.Delim('}') { return errors.New("invalid durable JSON object terminator") }
 case '[':
  for decoder.More() {
   if err := walkUniqueDurableJSONBounded(decoder, depth+1, budget); err != nil { return err }
  }
  if *budget <= 0 { return errors.New("durable JSON token budget exceeded") }
  *budget--
  end, err := decoder.Token()
  if err != nil || end != json.Delim(']') { return errors.New("invalid durable JSON array terminator") }
 default:
  return errors.New("unexpected durable JSON delimiter")
 }
 return nil
}
