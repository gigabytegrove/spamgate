package backupverify

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
)

// validateUniqueJSONKeys rejects ambiguous object members at every nesting
// level, including entries in the files array. encoding/json normally accepts
// duplicates and uses the last value, which is unsafe for signed inventories.
func validateUniqueJSONKeys(data []byte) error {
 dec := json.NewDecoder(bytes.NewReader(data))
 if err := consumeJSONValue(dec, 0); err != nil { return err }
 if _, err := dec.Token(); err != io.EOF {
  if err == nil { return errors.New("trailing backup manifest JSON") }
  return err
 }
 return nil
}

const maxManifestJSONDepth = 32

func consumeJSONValue(dec *json.Decoder, depth int) error {
 if depth > maxManifestJSONDepth { return errors.New("backup manifest JSON too deeply nested") }
 token, err := dec.Token()
 if err != nil { return err }
 delim, ok := token.(json.Delim)
 if !ok { return nil }
 switch delim {
 case '{':
  seen := make(map[string]struct{})
  for dec.More() {
   raw, err := dec.Token()
   if err != nil { return err }
   key, ok := raw.(string)
   if !ok { return errors.New("invalid backup manifest object key") }
   if _, exists := seen[key]; exists { return fmt.Errorf("duplicate backup manifest JSON key %q", key) }
   seen[key] = struct{}{}
   if err := consumeJSONValue(dec, depth+1); err != nil { return err }
  }
  end, err := dec.Token()
  if err != nil { return err }
  if end != json.Delim('}') { return errors.New("invalid backup manifest object terminator") }
 case '[':
  for dec.More() {
   if err := consumeJSONValue(dec, depth+1); err != nil { return err }
  }
  end, err := dec.Token()
  if err != nil { return err }
  if end != json.Delim(']') { return errors.New("invalid backup manifest array terminator") }
 default:
  return errors.New("invalid backup manifest JSON delimiter")
 }
 return nil
}
