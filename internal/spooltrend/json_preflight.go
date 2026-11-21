package spooltrend

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
)

// validateJSON rejects ambiguous duplicate object keys, excessive nesting and
// trailing values before the snapshot is decoded. It covers nested objects too.
func validateJSON(data []byte) error {
 d:=json.NewDecoder(bytes.NewReader(data))
 if err:=walkJSON(d,0);err!=nil{return err}
 if _,err:=d.Token();err!=io.EOF {
  if err==nil{return errors.New("multiple JSON values")}
  return err
 }
 return nil
}
func walkJSON(d *json.Decoder, depth int) error {
 if depth>64{return errors.New("JSON nesting exceeds 64")}
 token,err:=d.Token()
 if err!=nil{return err}
 delim,ok:=token.(json.Delim)
 if !ok{return nil}
 switch delim {
 case '{':
  seen:=make(map[string]struct{})
  for d.More(){
   k,err:=d.Token();if err!=nil{return err}
   key,ok:=k.(string);if !ok{return errors.New("invalid object key")}
   if _,exists:=seen[key];exists{return fmt.Errorf("duplicate JSON key %q",key)}
   seen[key]=struct{}{}
   if err:=walkJSON(d,depth+1);err!=nil{return err}
  }
  end,err:=d.Token();if err!=nil{return err}
  if end!=json.Delim('}'){return errors.New("invalid object ending")}
 case '[':
  for d.More(){if err:=walkJSON(d,depth+1);err!=nil{return err}}
  end,err:=d.Token();if err!=nil{return err}
  if end!=json.Delim(']'){return errors.New("invalid array ending")}
 default:return errors.New("unexpected JSON delimiter")
 }
 return nil
}
