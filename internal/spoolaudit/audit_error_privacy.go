package spoolaudit

import (
 "errors"
 "io/fs"
 "strings"
)

// auditReadFailure returns a fixed, privacy-safe category. In particular,
// never search for diagnostic keywords anywhere in an error: untrusted JSON
// object names can appear in decoder errors and spoof a different category.
func auditReadFailure(err error) string {
 if err==nil {return "record validation failed"}
 if errors.Is(err,fs.ErrPermission) {return "record access denied"}
 if errors.Is(err,fs.ErrNotExist) {return "record disappeared during audit"}
 message:=err.Error()
 switch {
 case hasAuditErrorPrefix(message,"spool record changed during read"),
      hasAuditErrorPrefix(message,"spool path changed during open"),
      hasAuditErrorPrefix(message,"spool directory changed during audit"),
      hasAuditErrorPrefix(message,"record changed during audit"):
  return "record changed during audit; retry read-only inspection"
 case hasAuditErrorPrefix(message,"unsafe spool metadata: spool original must have exactly one hard link"),
      hasAuditErrorPrefix(message,"unsafe opened spool metadata: spool original must have exactly one hard link"):
  return "unsafe record hard link count"
 case hasAuditErrorPrefix(message,"unsafe spool metadata: spool original must be private and owner-readable"),
      hasAuditErrorPrefix(message,"unsafe opened spool metadata: spool original must be private and owner-readable"):
  return "unsafe record private permissions"
 case hasAuditErrorPrefix(message,"unsafe spool metadata"),
      hasAuditErrorPrefix(message,"unsafe opened spool metadata"):
  return "unsafe record file metadata"
 case hasAuditErrorPrefix(message,"not a bounded regular spool record"):
  return "record is not a bounded regular file"
 case hasAuditErrorPrefix(message,"immutable envelope/original digest mismatch"),
      hasAuditErrorPrefix(message,"mutable state digest mismatch"):
  return "record integrity digest mismatch"
 case hasAuditErrorPrefix(message,"invalid or ambiguous spool JSON: spool JSON contains duplicate object key"):
  return "invalid or ambiguous record JSON: duplicate object key"
 case hasAuditErrorPrefix(message,"invalid or ambiguous spool JSON: spool JSON contains invalid Unicode escape"):
  return "invalid or ambiguous record JSON: invalid Unicode escape"
 case hasAuditErrorPrefix(message,"invalid or ambiguous spool JSON"),
      hasAuditErrorPrefix(message,"invalid spool JSON"):
  return "invalid or ambiguous record JSON"
 case hasAuditErrorPrefix(message,"invalid persisted scan"),
      hasAuditErrorPrefix(message,"persisted scan"),
      hasAuditErrorPrefix(message,"scan envelope"):
  return "invalid persisted scan evidence"
 case hasAuditErrorPrefix(message,"invalid durable timestamp"),
      hasAuditErrorPrefix(message,"durable timestamp"):
  return "invalid durable timestamp metadata"
 case hasAuditErrorPrefix(message,"invalid durable state"),
      hasAuditErrorPrefix(message,"durable state"):
  return "invalid durable delivery-state metadata"
 case hasAuditErrorPrefix(message,"durable envelope noncanonical field alias"):
  return "invalid durable envelope metadata: noncanonical field alias"
 case hasAuditErrorPrefix(message,"invalid durable envelope"),
      hasAuditErrorPrefix(message,"durable envelope"),
      hasAuditErrorPrefix(message,"durable spool"):
  return "invalid durable envelope metadata"
 default:
  return "record could not be validated"
 }
}

// A category must be the beginning of the trusted validator message, not
// arbitrary text embedded in a hostile field name. A word boundary prevents
// a longer, unrelated prefix from being treated as the validator's category.
func hasAuditErrorPrefix(message,prefix string) bool {
 if !strings.HasPrefix(message,prefix) {return false}
 if len(message)==len(prefix) {return true}
 switch message[len(prefix)] {
 case ':',' ',';',',','(':
  return true
 default:
  return false
 }
}
