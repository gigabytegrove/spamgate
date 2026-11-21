package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "strings"
)

func decodeSample(raw string)(comparisonSample,error){
 var s comparisonSample
 dec:=json.NewDecoder(strings.NewReader(raw))
 tok,err:=dec.Token();if err!=nil{return s,err}
 if tok!=json.Delim('{'){return s,errors.New("sample must be a JSON object")}
 seen:=map[string]bool{}
 for dec.More(){
  k,err:=dec.Token();if err!=nil{return s,err}
  key,ok:=k.(string);if !ok{return s,errors.New("invalid key")}
  if seen[key]{return s,fmt.Errorf("duplicate field %q",key)};seen[key]=true
  var rawValue json.RawMessage
  if err:=dec.Decode(&rawValue);err!=nil{return s,err}
  if string(rawValue)=="null"{return s,fmt.Errorf("null field %q",key)}
  switch key{
  case "id":
   if err:=json.Unmarshal(rawValue,&s.ID);err!=nil{return s,err}
  case "truth":
   if err:=json.Unmarshal(rawValue,&s.Truth);err!=nil{return s,err}
  case "score":
   if err:=json.Unmarshal(rawValue,&s.Score);err!=nil{return s,err}
  default:return s,fmt.Errorf("unknown field %q",key)
  }
 }
 tok,err=dec.Token();if err!=nil{return s,err}
 if tok!=json.Delim('}'){return s,errors.New("invalid object end")}
 if _,err:=dec.Token();err!=io.EOF{return s,errors.New("trailing JSON content")}
 for _,k:=range []string{"id","truth","score"}{if !seen[k]{return s,fmt.Errorf("missing field %q",k)}}
 if s.ID==""||s.Truth==""{return s,errors.New("empty id or truth")}
 return s,nil
}
