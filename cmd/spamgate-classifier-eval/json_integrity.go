package main

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
)

// rejectDuplicateJSONKeys validates the entire JSON token stream, including
// nested objects and escaped-key aliases, before typed corpus decoding.
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

// validateCorpusSchema rejects omitted or null labels/scores. Go's default
// struct decoding would otherwise silently turn missing spam into false and
// missing score into zero, contaminating acceptance metrics.
func validateCorpusSchema(payload []byte) error {
 var records []json.RawMessage
 if err:=json.Unmarshal(payload,&records);err!=nil{return fmt.Errorf("corpus must be an array of samples: %w",err)}
 if records==nil{return errors.New("corpus must be a non-null array")}
 for i,record:=range records {
  var fields map[string]json.RawMessage
  if err:=json.Unmarshal(record,&fields);err!=nil{return fmt.Errorf("sample %d must be an object: %w",i,err)}
  if fields==nil{return fmt.Errorf("sample %d must be a non-null object",i)}
  for _,key:=range []string{"id","tenant","spam","score"} {
   raw,ok:=fields[key]
   if !ok{return fmt.Errorf("sample %d missing required field %q",i,key)}
   if bytes.Equal(bytes.TrimSpace(raw),[]byte("null")){return fmt.Errorf("sample %d field %q must not be null",i,key)}
  }
  var spam bool
  if err:=json.Unmarshal(fields["spam"],&spam);err!=nil{return fmt.Errorf("sample %d spam must be boolean: %w",i,err)}
  var score float64
  if err:=json.Unmarshal(fields["score"],&score);err!=nil{return fmt.Errorf("sample %d score must be numeric: %w",i,err)}
  for _,key:=range []string{"id","tenant"} {
   var value string
   if err:=json.Unmarshal(fields[key],&value);err!=nil{return fmt.Errorf("sample %d %s must be string: %w",i,key,err)}
  }
 }
 return nil
}
