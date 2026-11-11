package archiveguard

import (
 "archive/zip"
 "bytes"
 "errors"
 "testing"
)

func orderedArchive(t *testing.T, names ...string) []byte {
 t.Helper()
 var b bytes.Buffer
 w := zip.NewWriter(&b)
 for _, name := range names {
  entry, err := w.Create(name)
  if err != nil { t.Fatal(err) }
  if _, err := entry.Write([]byte("x")); err != nil { t.Fatal(err) }
 }
 if err := w.Close(); err != nil { t.Fatal(err) }
 return b.Bytes()
}

func TestRejectFileParentCollisionInEitherOrder(t *testing.T) {
 for _, names := range [][]string{
  {"docs", "docs/readme.txt"},
  {"docs/readme.txt", "docs"},
  {"docs", "docs/nested/readme.txt"},
  {"docs/nested/readme.txt", "docs"},
  {"DOCS", "docs/readme.txt"},
  {"docs/readme.txt", "DOCS"},
 } {
  data := orderedArchive(t, names...)
  _, err := Inspect(bytes.NewReader(data), int64(len(data)), limits())
  if !errors.Is(err, ErrUnsafe) { t.Errorf("%v: expected ErrUnsafe, got %v", names, err) }
 }
}

func TestAllowImplicitDirectoryParents(t *testing.T) {
 data := orderedArchive(t, "docs/readme.txt", "docs/notes.txt")
 report, err := Inspect(bytes.NewReader(data), int64(len(data)), limits())
 if err != nil { t.Fatal(err) }
 if report.Files != 2 { t.Fatalf("files=%d", report.Files) }
}
