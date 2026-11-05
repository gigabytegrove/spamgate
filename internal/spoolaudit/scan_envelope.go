package spoolaudit

import (
 "bytes"
 "encoding/json"
 "errors"
 "slices"
 "strings"
)

// validateAuditScanEnvelope binds persisted scan evidence to the durable
// SMTP original. Legacy absent/null scans remain readable. Present scan
// identity must use exact JSON keys; encoding/json's case-insensitive struct
// matching must never reinterpret alternate-case keys as trusted identity.
func validateAuditScanEnvelope(rec record) error {
 if len(rec.Scan)==0 || bytes.Equal(bytes.TrimSpace(rec.Scan),[]byte("null")) {return nil}
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
  {"id",&id},{"sender",&sender},{"recipients",&recipients},
 } {
  raw,ok:=fields[field.name]
  if !ok || bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) {
   return errors.New("persisted scan envelope missing explicit identity fields")
  }
  if err:=json.Unmarshal(raw,field.target);err!=nil {
   return errors.New("invalid persisted scan envelope identity field")
  }
 }
 if id!=rec.ID || sender!=rec.Sender || !slices.Equal(recipients,rec.Recipients) {
  return errors.New("persisted scan envelope differs from durable SMTP original")
 }
 return nil
}
