package server

import (
 "errors"
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// The audit detail is stored with a message and returned through message APIs.
// Privileged command errors must never be persisted in that field.
func TestPostfixReleaseFailureAuditDetailIsSafeForMessageAPI(t *testing.T) {
 secret := "/etc/postfix/main.cf: permission denied; sudo: user spamgate not allowed"
 simulated := errors.New(secret)
 detail := postfixReleaseFailureAuditDetail()
 if detail == "" { t.Fatal("missing actionable audit detail") }
 if strings.Contains(detail, simulated.Error()) || strings.Contains(detail, "/etc/") || strings.Contains(detail, "sudo:") {
  t.Fatalf("privileged command error disclosed in persisted audit detail: %q", detail)
 }
 finding := core.Finding{Symbol:"POSTFIX_HOLD_RELEASE_COMMAND_FAILED", Source:"postfix/postsuper", Detail:detail}
 if finding.Detail != detail { t.Fatal("audit finding lost sanitized detail") }
 for _, want := range []string{"failed", "logs", "queue"} {
  if !strings.Contains(strings.ToLower(finding.Detail), want) {
   t.Errorf("audit detail lacks operational guidance %q: %q", want, finding.Detail)
  }
 }
}
