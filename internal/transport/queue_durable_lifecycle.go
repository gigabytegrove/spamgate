package transport

import (
 "bytes"
 "encoding/json"
 "errors"
 "io"
 "strings"
 "time"
)

// validateDurableLifecycleFields refuses zero-valued state invented by Go's
// permissive decoder. This runs on both published and crash-retained originals.
func validateDurableLifecycleFields(fields map[string]json.RawMessage) error {
 attempts,err:=strictDurableNonnegativeInteger(fields["attempts"])
 // Legacy records can exceed the current retry ceiling; recovery must
 // park them without sending again, rather than refusing startup.
 // Keep a bounded upper limit to reject nonsensical or corrupted counters.
 if err!=nil || attempts>1000000 { return errors.New("invalid durable delivery attempt count") }
 for _, key := range []string{"created","updated","next_attempt"} {
  value:=bytes.TrimSpace(fields[key])
  if len(value)==0 || value[0]!='"' { return errors.New("missing or invalid durable delivery timestamp") }
  var stamp string
  if err:=json.Unmarshal(value,&stamp);err!=nil { return errors.New("invalid durable delivery timestamp") }
  parsed,err:=time.Parse(time.RFC3339Nano,stamp)
  if err!=nil || parsed.IsZero() { return errors.New("invalid durable delivery timestamp") }
 }
 for _, key:=range []string{"delivered_at"} {
  value,ok:=fields[key];if !ok {continue}
  value=bytes.TrimSpace(value)
  if bytes.Equal(value,[]byte("null")) {return errors.New("invalid durable delivered timestamp")}
  if len(value)==0 || value[0]!='"' {return errors.New("invalid durable delivered timestamp")}
  var stamp string
  if err:=json.Unmarshal(value,&stamp);err!=nil {return errors.New("invalid durable delivered timestamp")}
  if stamp!="" { if _,err:=time.Parse(time.RFC3339Nano,stamp);err!=nil {return errors.New("invalid durable delivered timestamp")} }
 }
 return nil
}

// Keep strict decoding local to persisted state, never SMTP wire input.
func strictDurableInteger(raw []byte) (int64,error) {
 d:=json.NewDecoder(bytes.NewReader(raw));d.UseNumber()
 var v json.Number
 if err:=d.Decode(&v);err!=nil {return 0,errors.New("invalid integer")}
 var trailing any
 if err:=d.Decode(&trailing);err!=io.EOF {return 0,errors.New("trailing integer data")}
 if strings.ContainsAny(v.String(),".eE") {return 0,errors.New("fractional integer")}
 return v.Int64()
}
