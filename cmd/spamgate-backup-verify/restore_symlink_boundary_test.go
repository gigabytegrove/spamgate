package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestRestoreTargetResolvesSymlinkedAncestor(t *testing.T) {
 base := t.TempDir()
 actual := filepath.Join(base, "actual")
 if err := os.Mkdir(actual, 0700); err != nil { t.Fatal(err) }
 alias := filepath.Join(base, "alias")
 if err := os.Symlink(actual, alias); err != nil { t.Fatal(err) }
 target, err := resolveRestoreTarget(filepath.Join(alias, "missing", "restore"))
 if err != nil { t.Fatal(err) }
 want := filepath.Join(actual, "missing", "restore")
 if target != want { t.Fatalf("resolved %q, want %q", target, want) }
 if _, err := os.Stat(want); !os.IsNotExist(err) { t.Fatalf("resolution created a target: %v", err) }
}

func TestRestoreTargetRejectsDanglingSymlink(t *testing.T) {
 base := t.TempDir()
 alias := filepath.Join(base, "dangling")
 if err := os.Symlink(filepath.Join(base, "absent"), alias); err != nil { t.Fatal(err) }
 if _, err := resolveRestoreTarget(filepath.Join(alias, "restore")); err == nil {
  t.Fatal("dangling symlink accepted")
 }
}

func TestRestoreBoundaryRejectsActiveDataSymlinkAlias(t *testing.T) {
 base := t.TempDir()
 active := filepath.Join(base, "active")
 backup := filepath.Join(base, "backup")
 alias := filepath.Join(base, "alias")
 for _, path := range []string{active, backup} {
  if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
 }
 if err := os.Symlink(active, alias); err != nil { t.Fatal(err) }
 for _, target := range []string{alias, filepath.Join(alias, "new"), filepath.Join(alias, "missing", "new")} {
  t.Run(filepath.Base(target), func(t *testing.T) {
   var output bytes.Buffer
   err := run([]string{"-operation","restore","-backup",backup,"-manifest",filepath.Join(base,"missing-manifest"),"-key-file",filepath.Join(base,"missing-key"),"-active-data",active,"-target",target}, &output)
   if err == nil || !strings.Contains(err.Error(), "overlaps active data") { t.Fatalf("expected boundary rejection, got %v", err) }
   if output.Len() != 0 { t.Fatalf("unexpected success output: %q", output.String()) }
  })
 }
}
