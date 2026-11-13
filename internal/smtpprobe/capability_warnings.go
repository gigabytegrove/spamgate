package smtpprobe

import "strings"

// capabilityWarnings describes malformed or internally inconsistent EHLO
// advertisements. The greeting/identity line is never inspected as an extension.
// Warnings are stable identifiers, not assertions that mail delivery failed.
func capabilityWarnings(lines []string) []string {
 warnings := []string{}
 seenWarning := map[string]bool{}
 add := func(code string) {
  if !seenWarning[code] {
   seenWarning[code] = true
   warnings = append(warnings, code)
  }
 }
 if len(lines) < 2 { return warnings }
 seen := map[string]bool{}
 chunking, binaryMIME := false, false
 for _, line := range lines[1:] {
  fields := strings.Fields(line)
  if len(fields) == 0 { add("EMPTY_EXTENSION_LINE"); continue }
  keyword := strings.ToUpper(fields[0])
  canonical := keyword
  if strings.HasPrefix(keyword, "AUTH=") { canonical = "AUTH" }
  for i := 0; i < len(canonical); i++ {
   c := canonical[i]
   if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
    add("MALFORMED_EXTENSION_KEYWORD")
    canonical = ""
    break
   }
  }
  if canonical == "" { continue }
  if seen[canonical] { add("DUPLICATE_EXTENSION") }
  seen[canonical] = true
  switch canonical {
  case "STARTTLS", "CHUNKING", "BINARYMIME", "8BITMIME", "SMTPUTF8", "PIPELINING":
   if len(fields) != 1 { add("UNEXPECTED_EXTENSION_PARAMETERS"); continue }
   if canonical == "CHUNKING" { chunking = true }
   if canonical == "BINARYMIME" { binaryMIME = true }
  case "AUTH":
   mechanisms := fields[1:]
   if keyword != "AUTH" { mechanisms = append([]string{keyword[len("AUTH="):]}, mechanisms...) }
   valid := 0
   mechanismsSeen := make(map[string]bool, len(mechanisms))
   for _, mechanism := range mechanisms {
    if validAuthMechanism(mechanism) {
     valid++
     normalized := strings.ToUpper(mechanism)
     if mechanismsSeen[normalized] { add("DUPLICATE_AUTH_MECHANISM") }
     mechanismsSeen[normalized] = true
    } else { add("MALFORMED_AUTH_MECHANISM") }
   }
   if valid == 0 { add("EMPTY_AUTH_ADVERTISEMENT") }
  }
 }
 if binaryMIME && !chunking { add("BINARYMIME_WITHOUT_CHUNKING") }
 return warnings
}
