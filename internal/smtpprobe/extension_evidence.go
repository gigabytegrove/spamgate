package smtpprobe

import "strings"

// ExtensionEvidence describes only what a successful EHLO response advertised.
// It is not evidence that a mail transaction or extension command succeeds.
type ExtensionEvidence struct {
 PIPELINING bool `json:"pipelining"`
 EightBitMIME bool `json:"eight_bit_mime"`
 SMTPUTF8 bool `json:"smtp_utf8"`
 CHUNKING bool `json:"chunking"`
 BinaryMIME bool `json:"binary_mime"`
 DSN bool `json:"dsn"`
 EnhancedStatusCodes bool `json:"enhanced_status_codes"`
 REQUIRETLS bool `json:"require_tls"`
 Warnings []string `json:"warnings"`
}

// inspectExtensions never interprets the first EHLO line as an extension.
// The supported extensions are parameterless per their SMTP specifications.
// Malformed or duplicated advertisements do not count as reliable evidence.
func inspectExtensions(lines []string) ExtensionEvidence {
 e := ExtensionEvidence{Warnings: []string{}}
 if len(lines) < 2 { return e }
 known := map[string]bool{
  "PIPELINING": true, "8BITMIME": true, "SMTPUTF8": true,
  "CHUNKING": true, "BINARYMIME": true, "DSN": true, "REQUIRETLS": true,
  "ENHANCEDSTATUSCODES": true,
 }
 counts := map[string]int{}
 invalid := map[string]bool{}
 for _, line := range lines[1:] {
  fields := strings.Fields(line)
  if len(fields) == 0 { continue }
  // Tokenize the ASCII keyword before validating the entire advertisement.
  // strings.Fields alone would silently ignore a trailing NUL or Unicode
  // zero-width character, hiding a malformed known extension from diagnostics.
  keyword := smtpExtensionLeadingKeyword(line)
  if keyword == "" { continue }
  if !known[keyword] { continue }
  counts[keyword]++
  if len(fields) != 1 || line != fields[0] || !smtpExtensionASCIIKeyword(line) { invalid[keyword] = true }
 }
 for _, keyword := range []string{"PIPELINING", "8BITMIME", "SMTPUTF8", "CHUNKING", "BINARYMIME", "DSN", "REQUIRETLS", "ENHANCEDSTATUSCODES"} {
  if counts[keyword] > 1 { e.Warnings = append(e.Warnings, "DUPLICATE_"+keyword+"_EXTENSION") }
  if invalid[keyword] { e.Warnings = append(e.Warnings, "MALFORMED_"+keyword+"_EXTENSION") }
  if counts[keyword] != 1 || invalid[keyword] { continue }
  switch keyword {
  case "PIPELINING": e.PIPELINING = true
  case "8BITMIME": e.EightBitMIME = true
  case "SMTPUTF8": e.SMTPUTF8 = true
  case "CHUNKING": e.CHUNKING = true
  case "BINARYMIME": e.BinaryMIME = true
  case "DSN": e.DSN = true
  case "ENHANCEDSTATUSCODES": e.EnhancedStatusCodes = true
  case "REQUIRETLS": e.REQUIRETLS = true
  }
 }
 return e
}

func extensionEvidenceFindings(before, after ExtensionEvidence, postTLS bool) []Finding {
 findings := []Finding{}
 prefix := "EHLO"
 if postTLS { prefix = "POST_TLS_EHLO" }
 for _, warning := range after.Warnings {
  findings = append(findings, Finding{
   Code: prefix+"_"+warning, Severity:"warning",
   Message:"SMTP extension advertisement is malformed or duplicated; do not treat this extension as verified capability evidence",
  })
 }
 if !postTLS { return findings }
 // A change is a diagnostic observation, not necessarily a server defect.
 changes := []struct{name string; old, new bool}{
  {"PIPELINING",before.PIPELINING,after.PIPELINING},
  {"8BITMIME",before.EightBitMIME,after.EightBitMIME},
  {"SMTPUTF8",before.SMTPUTF8,after.SMTPUTF8},
  {"CHUNKING",before.CHUNKING,after.CHUNKING},
  {"BINARYMIME",before.BinaryMIME,after.BinaryMIME},
  {"DSN",before.DSN,after.DSN},
  {"ENHANCEDSTATUSCODES",before.EnhancedStatusCodes,after.EnhancedStatusCodes},
  {"REQUIRETLS",before.REQUIRETLS,after.REQUIRETLS},
 }
 for _, c := range changes {
  if c.old == c.new { continue }
  // Ambiguous evidence cannot establish that an extension appeared/disappeared.
  if extensionWarning(before.Warnings,c.name) || extensionWarning(after.Warnings,c.name) { continue }
  findings = append(findings, Finding{
   Code: c.name+"_ADVERTISEMENT_CHANGED_AFTER_TLS", Severity:"info",
   Message:"SMTP extension advertisement changed after verified STARTTLS; inspect server policy before relying on this capability",
  })
 }
 return findings
}
func extensionWarning(warnings []string, name string) bool {
 for _, warning := range warnings {
  if warning == "DUPLICATE_"+name+"_EXTENSION" || warning == "MALFORMED_"+name+"_EXTENSION" { return true }
 }
 return false
}

// smtpExtensionASCIIKeyword refuses control characters and non-ASCII lookalikes
// even if a future caller supplies untrusted, pre-split EHLO lines.
// smtpExtensionLeadingKeyword extracts only the initial RFC-style ASCII token.
// Leading whitespace is skipped solely to identify a malformed known keyword;
// the original line must still pass strict validation before being trusted.
func smtpExtensionLeadingKeyword(line string) string {
 line = strings.TrimLeft(line, " \t")
 end := 0
 for end < len(line) {
  b := line[end]
  if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-') { break }
  end++
 }
 return strings.ToUpper(line[:end])
}

func smtpExtensionASCIIKeyword(line string) bool {
 if line == "" { return false }
 for i := 0; i < len(line); i++ {
  b := line[i]
  if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-') {
   return false
  }
 }
 return true
}
