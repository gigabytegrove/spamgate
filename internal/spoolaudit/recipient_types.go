package spoolaudit

import (
 "bytes"
 "encoding/json"
 "errors"
)

// validateDurableRecipients rejects JSON nulls and non-string recipients
// before Go's permissive string-slice decoder can turn null into "".
// Empty recipient strings are rejected: only the SMTP reverse-path sender
// can be empty, never an RCPT TO address.
func validateDurableRecipients(data []byte) error {
 var fields map[string]json.RawMessage
 if err:=json.Unmarshal(data,&fields);err!=nil || fields==nil {
  return errors.New("invalid durable spool JSON object")
 }
 raw,ok:=fields["recipients"]
 if !ok || bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) {
  return errors.New("durable spool recipients missing or null")
 }
 var items []json.RawMessage
 if err:=json.Unmarshal(raw,&items);err!=nil || items==nil || len(items)==0 || len(items)>1000 {
  return errors.New("invalid durable spool recipients array")
 }
 for _,item:=range items {
  if bytes.Equal(bytes.TrimSpace(item),[]byte("null")) {
   return errors.New("durable spool recipient cannot be null")
  }
  var address string
  if err:=json.Unmarshal(item,&address);err!=nil || address=="" {
   return errors.New("durable spool recipient must be a nonempty string")
  }
 }
 return nil
}
