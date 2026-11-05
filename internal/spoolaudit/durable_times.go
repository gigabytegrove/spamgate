package spoolaudit

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "time"
)

// validateDurableTimes distinguishes absent/null/incorrectly typed persisted
// timestamps from legitimate timestamp values before Go's zero-value decoding.
// A syntactically valid zero time remains a lifecycle finding, not a parse error.
func validateDurableTimes(data []byte) error {
 var fields map[string]json.RawMessage
 if err:=json.Unmarshal(data,&fields);err!=nil || fields==nil {
  return errors.New("invalid durable timestamp JSON object")
 }
 for _,name:=range []string{"created","updated","next_attempt"} {
  raw,ok:=fields[name]
  if !ok || bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) {
   return fmt.Errorf("durable timestamp %s missing or null",name)
  }
  var stamp string
  if err:=json.Unmarshal(raw,&stamp);err!=nil {
   return fmt.Errorf("durable timestamp %s must be a string",name)
  }
  if _,err:=time.Parse(time.RFC3339Nano,stamp);err!=nil {
   return fmt.Errorf("durable timestamp %s invalid: %w",name,err)
  }
 }
 // delivered_at is optional on queued, failed and legacy records. When
 // present, however, null and non-time values are never valid evidence.
 if raw,ok:=fields["delivered_at"];ok {
  if bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) {
   return errors.New("durable timestamp delivered_at is null")
  }
  var stamp string
  if err:=json.Unmarshal(raw,&stamp);err!=nil {
   return errors.New("durable timestamp delivered_at must be a string")
  }
  if _,err:=time.Parse(time.RFC3339Nano,stamp);err!=nil {
   return fmt.Errorf("durable timestamp delivered_at invalid: %w",err)
  }
 }
 return nil
}
