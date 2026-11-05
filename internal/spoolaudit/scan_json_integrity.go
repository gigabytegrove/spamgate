package spoolaudit

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
)

// rejectDuplicateScanKeysRecursive validates every JSON object, including
// objects nested inside arrays. Last-value-wins JSON decoding must not hide
// conflicting forensic evidence. Keys are compared after JSON unescaping.
func rejectDuplicateScanKeysRecursive(raw []byte) error {
 dec:=json.NewDecoder(bytes.NewReader(raw))
 if err:=walkScanJSON(dec,0);err!=nil{return err}
 if _,err:=dec.Token();err!=io.EOF {
  return errors.New("invalid persisted scan envelope trailing content")
 }
 return nil
}

const maxScanJSONDepth=128

func walkScanJSON(dec *json.Decoder,depth int) error {
 if depth>maxScanJSONDepth {
  return errors.New("invalid persisted scan envelope nesting depth")
 }
 token,err:=dec.Token()
 if err!=nil{return errors.New("invalid persisted scan envelope JSON")}
 delim,ok:=token.(json.Delim)
 if !ok{return nil}
 switch delim {
 case '{':
  seen:=make(map[string]struct{})
  for dec.More() {
   keyToken,err:=dec.Token()
   if err!=nil{return errors.New("invalid persisted scan envelope key")}
   key,ok:=keyToken.(string)
   if !ok{return errors.New("invalid persisted scan envelope key")}
   if _,exists:=seen[key];exists {
    return fmt.Errorf("persisted scan envelope duplicate key %q",key)
   }
   seen[key]=struct{}{}
   if err:=walkScanJSON(dec,depth+1);err!=nil{return err}
  }
  closing,err:=dec.Token()
  if err!=nil||closing!=json.Delim('}') {
   return errors.New("invalid persisted scan envelope object termination")
  }
 case '[':
  for dec.More() {
   if err:=walkScanJSON(dec,depth+1);err!=nil{return err}
  }
  closing,err:=dec.Token()
  if err!=nil||closing!=json.Delim(']') {
   return errors.New("invalid persisted scan envelope array termination")
  }
 default:
  return errors.New("invalid persisted scan envelope delimiter")
 }
 return nil
}
