package main

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
)

// rejectDuplicateJSONKeys prevents a corpus record from supplying conflicting
// labels, tenants or scores whose effective value depends on parser behavior.
// It checks every object, not just the outer sample array.
func rejectDuplicateJSONKeys(payload []byte) error {
 dec:=json.NewDecoder(bytes.NewReader(payload))
 if err:=scanJSONValue(dec,0);err!=nil{return err}
 if _,err:=dec.Token();err==io.EOF{return nil}else if err!=nil{return fmt.Errorf("trailing JSON: %w",err)}
 return errors.New("trailing JSON value")
}

func scanJSONValue(dec *json.Decoder,depth int) error {
 if depth>64{return errors.New("JSON nesting exceeds 64 levels")}
 tok,err:=dec.Token()
 if err!=nil{return fmt.Errorf("invalid JSON: %w",err)}
 delim,ok:=tok.(json.Delim)
 if !ok{return nil}
 switch delim {
 case '{':
  seen:=make(map[string]struct{})
  for dec.More(){
   keyTok,err:=dec.Token();if err!=nil{return fmt.Errorf("object key: %w",err)}
   key,ok:=keyTok.(string);if !ok{return errors.New("object key is not a string")}
   if _,exists:=seen[key];exists{return fmt.Errorf("duplicate JSON object key %q",key)}
   seen[key]=struct{}{}
   if err:=scanJSONValue(dec,depth+1);err!=nil{return err}
  }
  end,err:=dec.Token();if err!=nil{return err}
  if end!=json.Delim('}'){return errors.New("invalid object terminator")}
 case '[':
  for dec.More(){if err:=scanJSONValue(dec,depth+1);err!=nil{return err}}
  end,err:=dec.Token();if err!=nil{return err}
  if end!=json.Delim(']'){return errors.New("invalid array terminator")}
 default:
  return errors.New("unexpected JSON closing delimiter")
 }
 return nil
}
