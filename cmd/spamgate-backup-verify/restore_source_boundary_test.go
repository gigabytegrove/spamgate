package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestRestoreSourceBoundary(t *testing.T) {
 base := t.TempDir()
 source := filepath.Join(base, "backup")
 if err := os.MkdirAll(source, 0700); err != nil { t.Fatal(err) }
 outside := filepath.Join(base, "elsewhere")
 alias := filepath.Join(base, "backup-alias")
 if err := os.Symlink(source, alias); err != nil { t.Fatal(err) }
 cases := []struct { name, target string; reject bool }{
  {"same directory", source, true},
  {"source descendant", filepath.Join(source, "restored"), true},
  {"source nested descendant", filepath.Join(source, "missing", "restored"), true},
  {"source ancestor", base, true},
  {"source symlink alias", alias, true},
  {"source symlink descendant", filepath.Join(alias, "restored"), true},
  {"separate sibling", outside, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   err := checkRestoreSourceBoundary(source, tc.target)
   if tc.reject && (err == nil || !strings.Contains(err.Error(), "overlaps backup source")) {
    t.Fatalf("expected source overlap refusal, got %v", err)
   }
   if !tc.reject && err != nil { t.Fatalf("valid target rejected: %v", err) }
  })
 }
}

func TestRestoreCLIRejectsSourceOverlapBeforeCredentialRead(t *testing.T) {
 base := t.TempDir()
 backup := filepath.Join(base, "backup")
 active := filepath.Join(base, "active")
 if err := os.Mkdir(backup, 0700); err != nil { t.Fatal(err) }
 if err := os.Mkdir(active, 0700); err != nil { t.Fatal(err) }
 for _, target := range []string{backup, filepath.Join(backup, "restore"), base} {
  var output bytes.Buffer
  err := run([]string{
   "-operation", "restore",
   "-backup", backup,
   "-active-data", active,
   "-target", target,
   "-manifest", filepath.Join(base, "missing-manifest"),
   "-key-file", filepath.Join(base, "missing-key"),
  }, &output)
  if err == nil || !strings.Contains(err.Error(), "overlaps backup source") {
   t.Fatalf("target %q: expected source overlap refusal before credential read, got %v", target, err)
  }
  if output.Len() != 0 { t.Fatalf("unexpected success output: %s", output.String()) }
 }
}
