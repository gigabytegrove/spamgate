package core

import (
 "archive/zip"
 "bytes"
 "encoding/base64"
 "fmt"
 "strings"
 "testing"
)

func archiveMIMEFixture(t *testing.T, names ...string) []byte {
 t.Helper()
 var buf bytes.Buffer
 writer := zip.NewWriter(&buf)
 for _, name := range names {
  part, err := writer.Create(name)
  if err != nil { t.Fatal(err) }
  if _, err := part.Write([]byte("safe text")); err != nil { t.Fatal(err) }
 }
 if err := writer.Close(); err != nil { t.Fatal(err) }
 return []byte(fmt.Sprintf("From: sender@example.invalid\r\nTo: receiver@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: application/zip; name=\"archive.zip\"\r\nContent-Disposition: attachment; filename=\"archive.zip\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", base64.StdEncoding.EncodeToString(buf.Bytes())))
}

func archiveHasFinding(t *testing.T, raw []byte, symbol string) bool {
 t.Helper()
 findings, err := InspectMIMEAttachments(raw)
 if err != nil { t.Fatal(err) }
 for _, finding := range findings {
  if finding.Symbol == symbol {
   if finding.Score != 0 { t.Fatalf("inspection uncertainty must not score as malicious: %+v", finding) }
   return true
  }
 }
 return false
}

func TestArchiveGuardIntegratedWithMIME(t *testing.T) {
 tests := []struct {
  name string
  members []string
  finding string
 }{
  {"ordinary ZIP", []string{"docs/readme.txt"}, ""},
  {"duplicate case-insensitive member", []string{"docs/a.txt", "docs/A.TXT"}, "ARCHIVE_UNSAFE_STRUCTURE"},
  {"parent file collision", []string{"docs", "docs/a.txt"}, "ARCHIVE_UNSAFE_STRUCTURE"},
  {"path traversal", []string{"../outside.txt"}, "ARCHIVE_UNSAFE_STRUCTURE"},
  {"member limit", []string{"a", "b", "c", "d"}, ""},
 }
 for _, tc := range tests {
  t.Run(tc.name, func(t *testing.T) {
   raw := archiveMIMEFixture(t, tc.members...)
   findings, err := InspectMIMEAttachments(raw)
   if err != nil { t.Fatal(err) }
   found := false
   for _, f := range findings {
    if strings.HasPrefix(f.Symbol, "ARCHIVE_UNSCANNED") || f.Symbol == "ARCHIVE_UNSAFE_STRUCTURE" || f.Symbol == "ARCHIVE_INSPECTION_LIMIT" {
     if f.Score != 0 { t.Fatalf("unsafe structure must remain a zero-score inspection diagnostic: %+v", f) }
     if tc.finding == "" { t.Fatalf("unexpected archive inspection failure: %+v", findings) }
     if f.Symbol == tc.finding { found = true }
    }
   }
   if tc.finding != "" && !found { t.Fatalf("missing %s: %+v", tc.finding, findings) }
  })
 }
}

func TestArchiveGuardDetectsMemberCountExhaustion(t *testing.T) {
 names := make([]string, archiveMaxEntries+1)
 for i := range names { names[i] = fmt.Sprintf("member-%03d.txt", i) }
 if !archiveHasFinding(t, archiveMIMEFixture(t, names...), "ARCHIVE_INSPECTION_LIMIT") {
  t.Fatal("archive with excess entries was not marked unscanned")
 }
}
