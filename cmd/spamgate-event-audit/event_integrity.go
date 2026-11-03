package main

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "unicode"
 "strings"
 "unicode/utf8"
)

// decodeAuditEvent rejects ambiguous top-level JSON keys, including keys
// spelled differently with JSON Unicode escapes. Event histories are evidence,
// so accepting a last-wins duplicate would misstate operational counts.
func decodeAuditEvent(line []byte, out *event) error {
 if !utf8.Valid(line) { return errors.New("invalid UTF-8 event evidence") }
 dec := json.NewDecoder(bytes.NewReader(line))
 tok, err := dec.Token()
 if err != nil { return err }
 if tok != json.Delim('{') { return errors.New("event must be a JSON object") }
 seen := make(map[string]struct{}, 8)
 for dec.More() {
  keyToken, err := dec.Token()
  if err != nil { return err }
  key, ok := keyToken.(string)
  if !ok { return errors.New("event key is not a string") }
  folded := auditFoldKey(key)
  if _, exists := seen[folded]; exists { return fmt.Errorf("ambiguous event key %q", key) }
  seen[folded] = struct{}
  if err := validateAuditValue(dec, 1); err != nil { return fmt.Errorf("field %q: %w", key, err) }
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

// validateAuditValue recursively rejects duplicate keys in nested evidence.
// A bounded nesting depth avoids stack exhaustion from hostile JSONL records.
func validateAuditValue(dec *json.Decoder, depth int) error {
 if depth > 64 { return errors.New("JSON nesting exceeds 64 levels") }
 token, err := dec.Token()
 if err != nil { return err }
 delim, ok := token.(json.Delim)
 if !ok { return nil }
 switch delim {
 case '{':
  seen := make([]string, 0, 8)
  for dec.More() {
   keyToken, err := dec.Token()
   if err != nil { return err }
   key, ok := keyToken.(string)
   if !ok { return errors.New("object key is not a string") }
   folded := auditFoldKey(key)
   if _, exists := seen[folded]; exists { return fmt.Errorf("ambiguous nested JSON key %q", key) }
   seen[folded] = struct{}
   if err := validateAuditValue(dec, depth+1); err != nil { return err }
  }
  end, err := dec.Token()
  if err != nil { return err }
  if end != json.Delim('}') { return errors.New("invalid object terminator") }
 case '[':
  for dec.More() {
   if err := validateAuditValue(dec, depth+1); err != nil { return err }
  }
  end, err := dec.Token()
  if err != nil { return err }
  if end != json.Delim(']') { return errors.New("invalid array terminator") }
 default:
  return errors.New("unexpected JSON delimiter")
 }
 return nil
}

// auditFoldKey maps every Unicode simple-fold equivalence class to its
// smallest code point. Unlike lowercasing, this preserves EqualFold semantics
// for Kelvin signs, long-s and other non-ASCII aliases while avoiding
// quadratic comparisons on large attacker-controlled JSON objects.
func auditFoldKey(key string) string {
 var b strings.Builder
 b.Grow(len(key))
 for _, r := range key {
  canonical := r
  for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
   if next < canonical { canonical = next }
  }
  b.WriteRune(canonical)
 }
 return b.String()
}
