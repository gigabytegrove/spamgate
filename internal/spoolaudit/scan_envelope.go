package spoolaudit

import (
 "bytes"
 "encoding/json"
 "errors"
 "slices"
)

// validateAuditScanEnvelope requires an explicitly bound scan identity.
// A missing sender field must not be confused with the legitimate empty
// reverse-path sender used for SMTP delivery status notifications.
func validateAuditScanEnvelope(rec record) error {
 if len(rec.Scan)==0 || bytes.Equal(bytes.TrimSpace(rec.Scan),[]byte("null")) {return nil}
 var scan struct {
  ID *string `json:"id"`
  Sender *string `json:"sender"`
  Recipients *[]string `json:"recipients"`
 }
 if err:=json.Unmarshal(rec.Scan,&scan);err!=nil{return errors.New("invalid persisted scan envelope")}
 if scan.ID==nil || scan.Sender==nil || scan.Recipients==nil {
  return errors.New("persisted scan envelope missing explicit identity fields")
 }
 if *scan.ID!=rec.ID || *scan.Sender!=rec.Sender || !slices.Equal(*scan.Recipients,rec.Recipients) {
  return errors.New("persisted scan envelope differs from durable SMTP original")
 }
 return nil
}
