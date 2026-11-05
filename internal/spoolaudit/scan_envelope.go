package spoolaudit

import (
 "bytes"
 "encoding/json"
 "errors"
 "slices"
)

// A signed scan is still not trusted as a description of a different SMTP
// envelope. Keep this check aligned with transport.validateSpoolScanEnvelope.
func validateAuditScanEnvelope(rec record) error {
 if len(rec.Scan)==0 || bytes.Equal(bytes.TrimSpace(rec.Scan),[]byte("null")) {return nil}
 var scan struct {
  ID string `json:"id"`
  Sender string `json:"sender"`
  Recipients []string `json:"recipients"`
 }
 if err:=json.Unmarshal(rec.Scan,&scan);err!=nil{return errors.New("invalid persisted scan envelope")}
 if scan.ID!=rec.ID || scan.Sender!=rec.Sender || !slices.Equal(scan.Recipients,rec.Recipients) {
  return errors.New("persisted scan envelope differs from durable SMTP original")
 }
 return nil
}
