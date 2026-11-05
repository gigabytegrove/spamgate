package spoolaudit

import (
 "bytes"
 "encoding/json"
 "errors"
 "slices"
)

// validateAuditScanEnvelope binds scan evidence to the durable SMTP original.
// Legacy absent/null scans are allowed; present scans require canonical,
// explicitly typed identity fields. Go's case-insensitive struct decoder must
// not turn a noncanonical field into trusted queue identity.
func validateAuditScanEnvelope(rec record) error {
 if len(rec.Scan)==0 || bytes.Equal(bytes.TrimSpace(rec.Scan),[]byte("null")) {return nil}
 var fields map[string]json.RawMessage
 if err:=json.Unmarshal(rec.Scan,&fields);err!=nil || fields==nil {
  return errors.New("invalid persisted scan envelope")
 }
 for _,name:=range []string{"id","sender","recipients"} {
  value,ok:=fields[name]
  if !ok || bytes.Equal(bytes.TrimSpace(value),[]byte("null")) {
   return errors.New("persisted scan envelope missing explicit identity fields")
  }
 }
 var scan struct {
  ID string `json:"id"`
  Sender string `json:"sender"`
  Recipients []string `json:"recipients"`
 }
 if err:=json.Unmarshal(rec.Scan,&scan);err!=nil {
  return errors.New("invalid persisted scan envelope")
 }
 if scan.ID!=rec.ID || scan.Sender!=rec.Sender || !slices.Equal(scan.Recipients,rec.Recipients) {
  return errors.New("persisted scan envelope differs from durable SMTP original")
 }
 return nil
}
