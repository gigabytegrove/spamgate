package spoolaudit

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "slices"
 "strings"
)

// validateAuditScanEnvelope binds persisted scan evidence to the durable
// SMTP original. Legacy absent/null scans remain readable. Present scan
// identity must use exact JSON keys; encoding/json's case-insensitive struct
// matching must never reinterpret alternate-case keys as trusted identity.
func validateAuditScanEnvelope(rec record) error {
 if len(rec.Scan)==0 || bytes.Equal(bytes.TrimSpace(rec.Scan),[]byte("null")) {return nil}
 if err:=rejectDuplicateScanKeys(rec.Scan);err!=nil {return err}
 var fields map[string]json.RawMessage
 if err:=json.Unmarshal(rec.Scan,&fields);err!=nil || fields==nil {
  return errors.New("invalid persisted scan envelope")
 }
 for key:=range fields {
  for _,name:=range []string{"id","sender","recipients"} {
   if key!=name && strings.EqualFold(key,name) {
    return errors.New("persisted scan envelope contains ambiguous identity key")
   }
  }
 }
 var id,sender string
 var recipients []string
 for _,field:=range []struct{name string; target any}{
  {"id",&id},{"sender",&sender},
 } {
  raw,ok:=fields[field.name]
  if !ok || bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) {
   return errors.New("persisted scan envelope missing explicit identity fields")
  }
  if err:=json.Unmarshal(raw,field.target);err!=nil {
   return errors.New("invalid persisted scan envelope identity field")
  }
 }
 // Decode each recipient separately. encoding/json otherwise accepts null
 // array elements as empty strings, which can alias a malformed recipient
 // with a persisted empty-string address.
 rawRecipients,ok:=fields["recipients"]
 if !ok || bytes.Equal(bytes.TrimSpace(rawRecipients),[]byte("null")) {
  return errors.New("persisted scan envelope missing explicit identity fields")
 }
 var items []json.RawMessage
 if err:=json.Unmarshal(rawRecipients,&items);err!=nil || items==nil {
  return errors.New("invalid persisted scan envelope recipients")
 }
 recipients=make([]string,0,len(items))
 for _,raw:=range items {
  if bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) {
   return errors.New("invalid persisted scan envelope null recipient")
  }
  var address string
  if err:=json.Unmarshal(raw,&address);err!=nil {
   return errors.New("invalid persisted scan envelope recipient type")
  }
  recipients=append(recipients,address)
 }
 if id!=rec.ID || sender!=rec.Sender || !slices.Equal(recipients,rec.Recipients) {
  return errors.New("persisted scan envelope differs from durable SMTP original")
 }
 return nil
}

 // rejectDuplicateScanKeys checks every top-level scan property before the
 // standard map decoder can silently apply its last-value-wins behavior.
 // Nested evidence remains opaque to this envelope identity validator.
func rejectDuplicateScanKeys(raw []byte) error {
 dec:=json.NewDecoder(bytes.NewReader(raw))
 first,err:=dec.Token()
 if err!=nil {return errors.New("invalid persisted scan envelope")}
 if first!=json.Delim('{') {return errors.New("invalid persisted scan envelope object")}
 seen:=make(map[string]struct{})
 for dec.More() {
  keyToken,err:=dec.Token()
  if err!=nil {return errors.New("invalid persisted scan envelope key")}
  key,ok:=keyToken.(string)
  if !ok {return errors.New("invalid persisted scan envelope key")}
  if _,exists:=seen[key];exists {return fmt.Errorf("persisted scan envelope duplicate key %q",key)}
  seen[key]=struct{}{}
  var value json.RawMessage
  if err:=dec.Decode(&value);err!=nil {return errors.New("invalid persisted scan envelope value")}
 }
 last,err:=dec.Token()
 if err!=nil || last!=json.Delim('}') {return errors.New("invalid persisted scan envelope termination")}
 if _,err:=dec.Token();err!=io.EOF {return errors.New("invalid persisted scan envelope trailing content")}
 return nil
}
