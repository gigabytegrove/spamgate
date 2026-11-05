package spoolaudit

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
)

// validateDurableState rejects absent or null delivery state metadata before
// encoding/json can silently substitute zero values. Integer fields must be
// JSON integers, not floating point, strings or booleans.
func validateDurableState(data []byte) error {
 var fields map[string]json.RawMessage
 if err:=json.Unmarshal(data,&fields);err!=nil || fields==nil {
  return errors.New("invalid durable state JSON object")
 }
 for _,name:=range []string{"state","size","attempts"} {
  raw,ok:=fields[name]
  if !ok || bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) {
   return fmt.Errorf("durable state %s missing or null",name)
  }
  switch name {
  case "state":
   var state string
   if err:=json.Unmarshal(raw,&state);err!=nil {
    return errors.New("durable state must be a string")
   }
   switch state {
   case "queued","delivering","dead","delivered","discard_pending":
   default:return errors.New("durable state has unknown value")
   }
  default:
   var integer int
   if err:=json.Unmarshal(raw,&integer);err!=nil {
    return fmt.Errorf("durable state %s must be an integer",name)
   }
   if name=="size" && (integer<1 || integer>10<<20) {
    return errors.New("durable state size out of bounds")
   }
   if name=="attempts" && integer<0 {
    return errors.New("durable state attempts negative")
   }
  }
 }
 return nil
}
