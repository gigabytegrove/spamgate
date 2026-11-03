package main

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "strings"
)

// decodeAuditEvent rejects ambiguous top-level JSON keys, including keys
// spelled differently with JSON Unicode escapes. Event histories are evidence,
// so accepting a last-wins duplicate would misstate operational counts.
func decodeAuditEvent(line []byte, out *event) error {
 dec := json.NewDecoder(bytes.NewReader(line))
 tok, err := dec.Token()
 if err != nil { return err }
 if tok != json.Delim('{') { return errors.New("event must be a JSON object") }
 seen := make(map[string]struct{})
 for dec.More() {
  keyToken, err := dec.Token()
  if err != nil { return err }
  key, ok := keyToken.(string)
  if !ok { return errors.New("event key is not a string") }
  if _, exists := seen[key]; exists { return fmt.Errorf("duplicate event key %q", key) }
  seen[key] = struct{}{}
  var raw json.RawMessage
  if err := dec.Decode(&raw); err != nil { return err }
 }
 if _, err := dec.Token(); err != nil { return err }
 if _, err := dec.Token(); err != io.EOF {
  if err == nil { return errors.New("trailing JSON value") }
  return err
 }
 if err := json.Unmarshal(line, out); err != nil { return err }
 if strings.EqualFold(strings.TrimSpace(out.Connector), "milter") {
  if len(out.Findings) > 0 && string(out.Findings) != "null" {
   var findings []json.RawMessage
   if err := json.Unmarshal(out.Findings, &findings); err != nil { return fmt.Errorf("invalid findings array: %w", err) }
   if findings == nil { return errors.New("findings must be an array") }
  }
 }
 return nil
}
