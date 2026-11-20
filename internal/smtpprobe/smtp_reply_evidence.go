package smtpprobe

import "fmt"

// smtpReplyClassFinding preserves observed SMTP response class without
// guessing whether a remote server will accept a later retry. No commands
// are issued by this diagnostic.
func smtpReplyClassFinding(stage string, code int) *Finding {
 if code < 400 || code > 599 { return nil }
 kind := "PERMANENT"
 message := "SMTP peer returned a 5xx reply; inspect the server policy and logs before retrying"
 if code < 500 {
  kind = "TEMPORARY"
  message = "SMTP peer returned a 4xx reply; inspect the server and retry policy"
 }
 return &Finding{
  Code: fmt.Sprintf("%s_%s_REPLY", stage, kind),
  Severity: "warning",
  Message: fmt.Sprintf("%s (observed SMTP reply %d; no message was submitted)", message, code),
 }
}

func smtpReplyClassFindings(r Result) []Finding {
 findings := []Finding{}
 for _, entry := range []struct{stage string; code int}{
  {"GREETING", r.BannerCode},
  {"EHLO", r.EHLOCode},
  {"STARTTLS", r.StartTLSReplyCode},
  {"POST_TLS_EHLO", r.PostTLSEHLOCode},
 } {
  // Never infer a reply from zero/unattempted stages.
  if f := smtpReplyClassFinding(entry.stage, entry.code); f != nil {
   findings = append(findings, *f)
  }
 }
 return findings
}
