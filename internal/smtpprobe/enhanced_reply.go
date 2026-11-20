package smtpprobe

import (
 "fmt"
 "strings"
)

// observedEnhancedStatus accepts only an unambiguous RFC 3463-style status
// at the beginning of every reply text line. The leading class must match
// the SMTP reply class. It never returns untrusted free-form server text.
func observedEnhancedStatus(code int, lines []string) string {
 if code < 200 || code > 599 || len(lines) == 0 { return "" }
 var observed string
 for _, line := range lines {
  fields := strings.Fields(line)
  if len(fields) == 0 { return "" }
  token := fields[0]
  parts := strings.Split(token, ".")
  if len(parts) != 3 || len(parts[0]) != 1 || parts[0][0] != byte('0'+code/100) { return "" }
  for _, part := range parts[1:] {
   if len(part) < 1 || len(part) > 3 { return "" }
   for i:=0;i<len(part);i++ { if part[i]<'0' || part[i]>'9' { return "" } }
  }
  if observed != "" && observed != token { return "" }
  observed = token
 }
 return observed
}

// Only observed non-success replies are reported. Enhanced status is evidence,
// not proof that SMTP AUTH, message acceptance, or delivery succeeded.
func enhancedReplyFindings(r Result) []Finding {
 out := []Finding{}
 for _, item := range []struct{stage string; code int; enhanced string}{
  {"GREETING",r.BannerCode,r.BannerEnhancedCode},
  {"EHLO",r.EHLOCode,r.EHLOEnhancedCode},
  {"STARTTLS",r.StartTLSReplyCode,r.StartTLSEnhancedCode},
  {"POST_TLS_EHLO",r.PostTLSEHLOCode,r.PostTLSEHLOEnhancedCode},
 } {
  if item.code < 400 || item.code > 599 || item.enhanced == "" { continue }
  // Guard manually constructed Result values as well as probe observations.
  if observedEnhancedStatus(item.code,[]string{item.enhanced}) != item.enhanced { continue }
  out=append(out,Finding{Code:item.stage+"_ENHANCED_REPLY",Severity:"info",
   Message:fmt.Sprintf("Observed SMTP reply %d with enhanced status %s; no message was submitted",item.code,item.enhanced)})
 }
 return out
}
