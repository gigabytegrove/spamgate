package backup

import (
 "strings"
 "sort"
 "testing"
 "time"
)

func TestPortableBackupPathEvidence(t *testing.T) {
 valid := []string{"state.json", "mail/2026/message.eml", "company/report.v1.json", "compact", "COM10.txt", "company/CONNECTION.txt", "COM0.txt", "LPT10.txt"}
 for _, name := range valid {
  if !safeName(name) { t.Errorf("valid portable name rejected: %q", name) }
 }
 invalid := []string{"CON", "con.txt", "mail/NUL.json", "AUX", "PRN.txt", "COM1", "com9.log", "LPT1", "lpt9.txt", "CONIN$", "CONOUT$", "mail/file.", "mail/folder./file", "mail/file:stream", "mail/what?.txt", "mail/star*.txt", "mail/pipe|name", "mail/less<name", "mail/greater>name", "mail/quote\"name"}
 for _, name := range invalid {
  if safeName(name) { t.Errorf("unsafe portable name accepted: %q", name) }
  m := Manifest{Format:1, Product:"SpamGate", Created:time.Date(2026,11,1,0,0,0,0,time.UTC), Entries:[]Entry{{Path:name, Bytes:1, SHA256:strings.Repeat("a",64)}}}
  if err:=validateManifestSemantics(m);err==nil { t.Errorf("unsafe manifest path accepted: %q",name) }
 }
}

func TestBackupManifestCaseInsensitiveIdentity(t *testing.T) {
 cases := []struct {
  name string
  paths []string
  reject bool
 }{
  {"same-directory-case", []string{"Mail/a.eml", "mail/a.eml"}, true},
  {"case-folded-ancestor", []string{"Mail", "mail/a.eml"}, true},
  {"reverse-order-ancestor", []string{"Mail/a.eml", "mail"}, true},
  {"unicode-case-fold", []string{"Ä/a.eml", "ä/a.eml"}, true},
  {"distinct-paths", []string{"Mail/a.eml", "mail/b.eml"}, false},
  {"distinct-subtrees", []string{"Mail/a.eml", "mail/b.eml", "other/c.eml"}, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   entries := make([]Entry, 0, len(tc.paths))
   for _, path := range tc.paths {
    entries = append(entries, Entry{Path:path, Bytes:1, SHA256:strings.Repeat("a",64)})
   }
   // Manifest v1 mandates bytewise lexical ordering.
   sort.Slice(entries, func(i,j int) bool {return entries[i].Path < entries[j].Path})
   manifest := Manifest{Format:1, Product:"SpamGate", Created:time.Date(2026,11,1,0,0,0,0,time.UTC), Entries:entries}
   err := validateManifestSemantics(manifest)
   if (err != nil) != tc.reject {t.Fatalf("reject=%v, error=%v",tc.reject,err)}
  })
 }
}
