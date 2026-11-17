package backup

import (
 "strings"
 "testing"
 "time"
)

func TestPortableBackupPathEvidence(t *testing.T) {
 valid := []string{"state.json", "mail/2026/message.eml", "company/report.v1.json", "compact", "COM10.txt", "company/CONNECTION.txt"}
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
