package spoolaudit

import (
 "errors"
 "io/fs"
 "strings"
)

// auditReadFailure returns a bounded, privacy-safe diagnostic for a corrupt
// queue record. Decoder errors may contain arbitrary JSON object keys, which
// are attacker-controlled and can contain mailbox addresses or message text.
// Never forward those errors into retained reports or operator APIs.
func auditReadFailure(err error) string {
 if err==nil {return "record validation failed"}
 if errors.Is(err,fs.ErrPermission) {return "record access denied"}
 if errors.Is(err,fs.ErrNotExist) {return "record disappeared during audit"}
 message:=err.Error()
 switch {
 case strings.Contains(message,"changed during"),strings.Contains(message,"path changed"):
  return "record changed during audit; retry read-only inspection"
 case strings.Contains(message,"unsafe spool metadata"),strings.Contains(message,"unsafe opened spool metadata"):
  return "unsafe record file metadata"
 case strings.Contains(message,"not a bounded regular spool record"):
  return "record is not a bounded regular file"
 case strings.Contains(message,"digest mismatch"):
  return "record integrity digest mismatch"
 case strings.Contains(message,"invalid or ambiguous spool JSON"):
  return "invalid or ambiguous record JSON"
 case strings.Contains(message,"persisted scan"),strings.Contains(message,"scan envelope"):
  return "invalid persisted scan evidence"
 case strings.Contains(message,"durable timestamp"):
  return "invalid durable timestamp metadata"
 case strings.Contains(message,"durable state"):
  return "invalid durable delivery-state metadata"
 case strings.Contains(message,"durable envelope"),strings.Contains(message,"durable spool"):
  return "invalid durable envelope metadata"
 default:
  return "record could not be validated"
 }
}
