package spoolaudit

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
)

// validateDurableIdentity rejects absent, null, incorrectly typed and
// noncanonical durable envelope identity fields before decoding into a Go
// struct. In particular, encoding/json silently maps null strings to "".
// An empty SMTP MAIL FROM is valid, but the sender field must exist.
func validateDurableIdentity(data []byte) error {
 var fields map[string]json.RawMessage
 if err:=json.Unmarshal(data,&fields);err!=nil || fields==nil {
  return errors.New("invalid durable envelope JSON object")
 }
 for _,name:=range []string{"id","sender","recipients","raw"} {
  raw,ok:=fields[name]
  if !ok || bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) {
   return fmt.Errorf("durable envelope %s missing or null",name)
  }
  switch name {
  case "id","sender":
   var value string
   if err:=json.Unmarshal(raw,&value);err!=nil {
    return fmt.Errorf("durable envelope %s must be a string",name)
   }
   if name=="id" && !validID(value) {
    return errors.New("durable envelope id must be a lowercase 32-character hex ID")
   }
  case "raw":
   var value string
   if err:=json.Unmarshal(raw,&value);err!=nil {
    return errors.New("durable envelope raw must be a base64 string")
   }
  }
 }
 return validateDurableRecipients(data)
}
