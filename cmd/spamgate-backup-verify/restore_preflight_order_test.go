package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// Regression: active-data refusals must precede any credential reads.
// The credentials deliberately do not exist.
func TestRestoreActiveBoundaryPrecedesCredentialValidation(t *testing.T) {
 root := t.TempDir()
 backup := filepath.Join(root, "backup")
 if err := os.Mkdir(backup, 0700); err != nil { t.Fatal(err) }
 active := filepath.Join(root, "active")
 if err := os.Mkdir(active, 0700); err != nil { t.Fatal(err) }
 alias := filepath.Join(root, "alias")
 if err := os.Symlink(active, alias); err != nil { t.Fatal(err) }
 for _, target := range []string{active, filepath.Join(active, "child"), alias, filepath.Join(alias, "child")} {
  t.Run(filepath.Base(target), func(t *testing.T) {
   var out bytes.Buffer
   err := run([]string{
    "-operation", "restore", "-backup", backup,
    "-manifest", filepath.Join(root, "missing-manifest"),
    "-key-file", filepath.Join(root, "missing-key"),
    "-active-data", active, "-target", target,
   }, &out)
   if err == nil || !strings.Contains(err.Error(), "overlaps active data") {
    t.Fatalf("expected active boundary before credential access, got %v", err)
   }
   if out.Len() != 0 { t.Fatalf("unexpected output: %q", out.String()) }
  })
 }
}
