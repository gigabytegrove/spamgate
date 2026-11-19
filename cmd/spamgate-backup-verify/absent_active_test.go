package main

import (
 "os"
 "path/filepath"
 "testing"
)

func TestResolveAbsentActiveDataBoundary(t *testing.T) {
 root:=t.TempDir()
 missing:=filepath.Join(root,"not-installed","data")
 resolved,err:=resolveRestoreTarget(missing)
 if err!=nil { t.Fatal(err) }
 if resolved!=missing { t.Fatalf("resolved %q, want %q",resolved,missing) }
 target:=filepath.Join(root,"restore")
 if target==resolved || containsPath(target,resolved) || containsPath(resolved,target) {
  t.Fatal("unrelated restore incorrectly overlaps absent active data")
 }
}

func TestResolveActiveDataAliasWithMissingLeaf(t *testing.T) {
 root:=t.TempDir()
 actual:=filepath.Join(root,"actual")
 if err:=os.Mkdir(actual,0700);err!=nil { t.Fatal(err) }
 alias:=filepath.Join(root,"alias")
 if err:=os.Symlink(actual,alias);err!=nil { t.Fatal(err) }
 resolved,err:=resolveRestoreTarget(filepath.Join(alias,"data"))
 if err!=nil { t.Fatal(err) }
 if resolved!=filepath.Join(actual,"data") { t.Fatalf("symlink boundary not resolved: %q",resolved) }
}
