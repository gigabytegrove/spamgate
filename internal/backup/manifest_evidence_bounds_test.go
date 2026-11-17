package backup

import (
 "strings"
 "testing"
 "time"
)

func TestManifestEvidenceBoundsAndCanonicalOrder(t *testing.T) {
 digest := strings.Repeat("a", 64)
 base := func() Manifest {
  return Manifest{
   Format: 1, Product: "SpamGate",
   Created: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
   Entries: []Entry{{Path: "a.txt", Bytes: 1, SHA256: digest}, {Path: "b.txt", Bytes: 2, SHA256: digest}},
  }
 }
 if err := validateManifestSemantics(base()); err != nil { t.Fatalf("canonical evidence rejected: %v", err) }
 cases := []struct {
  name string
  mutate func(*Manifest)
 }{
  {"wrong product", func(m *Manifest) { m.Product = "Other" }},
  {"wrong format", func(m *Manifest) { m.Format = 2 }},
  {"no entries", func(m *Manifest) { m.Entries = nil }},
  {"duplicate path", func(m *Manifest) { m.Entries[1].Path = "a.txt" }},
  {"unsorted paths", func(m *Manifest) { m.Entries[0].Path = "z.txt" }},
  {"negative bytes", func(m *Manifest) { m.Entries[0].Bytes = -1 }},
  {"aggregate overflow", func(m *Manifest) { m.Entries[0].Bytes = maxBytes; m.Entries[1].Bytes = 1 }},
  {"single oversized", func(m *Manifest) { m.Entries[0].Bytes = maxBytes + 1 }},
  {"traversal", func(m *Manifest) { m.Entries[0].Path = "../escape" }},
  {"absolute path", func(m *Manifest) { m.Entries[0].Path = "/etc/passwd" }},
  {"file directory collision", func(m *Manifest) { m.Entries[0].Path = "mail"; m.Entries[1].Path = "mail/message.eml" }},
  {"file directory collision with intervening sibling", func(m *Manifest) { m.Entries = []Entry{{Path:"mail", SHA256:digest}, {Path:"mail-other", SHA256:digest}, {Path:"mail/message.eml", SHA256:digest}} }},
  {"reserved manifest", func(m *Manifest) { m.Entries[0].Path = manifestPath }},
  {"control character", func(m *Manifest) { m.Entries[0].Path = "a\n.txt" }},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   m := base()
   tc.mutate(&m)
   if err := validateManifestSemantics(m); err == nil {
    t.Fatal("invalid manifest evidence accepted")
   }
  })
 }
}

func TestManifestEvidenceRejectsExcessiveFileCount(t *testing.T) {
 m := Manifest{Format: 1, Product: "SpamGate", Created: time.Now().UTC(), Entries: make([]Entry, maxFiles+1)}
 if err := validateManifestSemantics(m); err == nil { t.Fatal("oversized manifest accepted") }
}
