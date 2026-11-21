package main

import (
 "encoding/json"
 "fmt"
 "io"
 "strings"
)

// decodeSample requires every scoring field exactly once. encoding/json's
// struct decoder silently accepts absent fields and duplicate keys.
func decodeSample(raw string) (Sample, error) {
 dec := json.NewDecoder(strings.NewReader(raw))
 tok, err := dec.Token()
 if err != nil { return Sample{}, err }
 if tok != json.Delim('{') { return Sample{}, fmt.Errorf("sample must be an object") }
 fields := make(map[string]json.RawMessage, 3)
 for dec.More() {
  keyToken, err := dec.Token()
  if err != nil { return Sample{}, err }
  key, ok := keyToken.(string)
  if !ok { return Sample{}, fmt.Errorf("invalid field key") }
  if key != "id" && key != "truth" && key != "score" { return Sample{}, fmt.Errorf("unknown field %q", key) }
  if _, exists := fields[key]; exists { return Sample{}, fmt.Errorf("duplicate field %q", key) }
  var value json.RawMessage
  if err := dec.Decode(&value); err != nil { return Sample{}, err }
  fields[key] = value
 }
 if _, err := dec.Token(); err != nil { return Sample{}, err }
 for _, key := range []string{"id", "truth", "score"} {
  if _, ok := fields[key]; !ok { return Sample{}, fmt.Errorf("missing field %q", key) }
  if strings.TrimSpace(string(fields[key])) == "null" { return Sample{}, fmt.Errorf("null field %q", key) }
 }
 var sample Sample
 if err := json.Unmarshal(fields["id"], &sample.ID); err != nil { return Sample{}, fmt.Errorf("id: %w", err) }
 if err := json.Unmarshal(fields["truth"], &sample.Truth); err != nil { return Sample{}, fmt.Errorf("truth: %w", err) }
 if err := json.Unmarshal(fields["score"], &sample.Score); err != nil { return Sample{}, fmt.Errorf("score: %w", err) }
 var extra any
 if err := dec.Decode(&extra); err != io.EOF { return Sample{}, fmt.Errorf("trailing JSON") }
 return sample, nil
}
