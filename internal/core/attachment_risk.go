package core

import (
 "path"
 "strings"
 "unicode"
 "unicode/utf8"
)

// attachmentNameFindings inspects decoded MIME filenames. A suspicious
// extension is evidence for scoring, not proof of malware.
func attachmentNameFindings(filename string) []AttachmentFinding {
 if filename == "" || filename == "unnamed attachment" { return nil }
 name := path.Base(strings.ReplaceAll(filename, "\\", "/"))
 lower := strings.ToLower(strings.TrimRight(name, " .\t"))
 out := make([]AttachmentFinding, 0, 3)
 add := func(symbol, detail string, score float64) {
  out = append(out, AttachmentFinding{Symbol: symbol, Detail: detail, Score: score})
 }
 for _, r := range name {
  if isFilenameBidiControl(r) {
   add("ATTACHMENT_NAME_BIDI", "Attachment filename contains bidirectional override/control characters", 3)
   break
  }
 }
 if strings.TrimRight(name, " .\t") != name {
  add("ATTACHMENT_NAME_TRAILING", "Attachment filename ends in ambiguous whitespace or dots", 1)
 }
 if riskyFilename(lower) {
  score := 4.0
  if hasMacroOfficeExtension(lower) { score = 2 }
  add("ATTACHMENT_RISKY_EXTENSION", "Attachment has an executable, script, or macro-enabled extension", score)
 }
 parts := strings.Split(lower, ".")
 if len(parts) >= 3 && riskyFilename("x."+parts[len(parts)-1]) && isDocumentDecoy(parts[len(parts)-2]) {
  add("ATTACHMENT_DOUBLE_EXTENSION", "Attachment filename disguises a dangerous suffix behind a document or media extension", 3)
 }
 return out
}
func hasMacroOfficeExtension(name string) bool {
 for _, suffix := range []string{".docm", ".xlsm", ".xll"} {
  if strings.HasSuffix(name, suffix) { return true }
 }
 return false
}
func isDocumentDecoy(ext string) bool {
 switch ext {
 case "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "webp", "mp3", "mp4", "zip":
  return true
 }
 return false
}
func isFilenameBidiControl(r rune) bool {
 return r == '\u061c' || r == '\u200e' || r == '\u200f' || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}

// Keep hostile CR/LF, terminal controls, bidi controls and huge filenames out
// of operational evidence, even if a MIME parser accepted the filename.
func attachmentLabel(name string) string {
 if name == "" { return "unnamed attachment" }
 var b strings.Builder
 b.Grow(min(len(name), 120))
 for _, r := range name {
  if unicode.IsControl(r) || isFilenameBidiControl(r) || r == '\u2028' || r == '\u2029' || r == utf8.RuneError { r = '_' }
  if b.Len()+utf8.RuneLen(r) > 120 { break }
  b.WriteRune(r)
 }
 if b.Len() == 0 { return "unnamed attachment" }
 return b.String()
}
