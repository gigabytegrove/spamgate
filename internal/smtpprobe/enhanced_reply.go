package smtpprobe

import (
 "fmt"
 "strings"
)

// observedEnhancedStatus accepts only canonical, bounded RFC 3463 status
// evidence consistently present at the start of every SMTP reply text line.
// It never preserves arbitrary server reply text.
func observedEnhancedStatus(code int, lines []string) string {
 if code < 200 || code > 599 || (code/100 != 2 && code/100 != 4 && code/100 != 5) || len(lines) == 0 || len(lines) > 100 { return "" }
 var observed string
 for _, line := range lines {
  if len(line) == 0 || len(line) > 512 || containsUnsafeReplyByte(line) { return "" }
  // Only ASCII space and tab delimit the status token. Unicode whitespace
  // must not transform a malformed wire response into trusted evidence.
  end := strings.IndexAny(line, " \t")
  if end < 0 { end = len(line) }
  token := line[:end]
  parts := strings.Split(token, ".")
  if len(parts) != 3 || len(parts[0]) != 1 || parts[0][0] != byte('0'+code/100) { return "" }
  for _, part := range parts[1:] {
   if len(part) < 1 || len(part) > 3 || (len(part) > 1 && part[0] == '0') { return "" }
   for i := 0; i < len(part); i++ { if part[i] < '0' || part[i] > '9' { return "" } }
  }
  if observed != "" && observed != token { return "" }
  observed = token
 }
 return observed
}

// Enhanced replies are observations, not authentication or delivery proof.
// Revalidate manually constructed Result values before emitting findings.
func enhancedReplyFindings(r Result) []Finding {
 out := []Finding{}
 for _, item := range []struct{stage string; code int; enhanced string}{
  {"GREETING",r.BannerCode,r.BannerEnhancedCode},
  {"EHLO",r.EHLOCode,r.EHLOEnhancedCode},
  {"STARTTLS",r.StartTLSReplyCode,r.StartTLSEnhancedCode},
  {"POST_TLS_EHLO",r.PostTLSEHLOCode,r.PostTLSEHLOEnhancedCode},
 } {
  if item.code < 400 || item.code > 599 || item.enhanced == "" { continue }
  if observedEnhancedStatus(item.code, []string{item.enhanced}) != item.enhanced { continue }
  out = append(out, Finding{Code:item.stage+"_ENHANCED_REPLY",Severity:"info",
   Message:fmt.Sprintf("Observed SMTP reply %d with enhanced status %s; no message was submitted",item.code,item.enhanced)})
 }
 return out
}


// containsUnsafeReplyByte refuses C0 controls (except ASCII HTAB, which is
// allowed as a token delimiter) and DEL. This validation also applies when
// callers construct Result values without passing through the wire parser.
func containsUnsafeReplyByte(line string) bool {
 for i := 0; i < len(line); i++ {
  b := line[i]
  if (b < 32 && b != '\t') || b == 127 { return true }
 }
 return false
}
