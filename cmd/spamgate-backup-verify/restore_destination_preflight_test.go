package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestColdRestoreDestinationPreflight(t *testing.T) {
 root := t.TempDir()
 existing := filepath.Join(root, "existing")
 if err := os.Mkdir(existing, 0700); err != nil { t.Fatal(err) }
 file := filepath.Join(root, "file")
 if err := os.WriteFile(file, []byte("x"), 0600); err != nil { t.Fatal(err) }
 alias := filepath.Join(root, "alias")
 if err := os.Symlink(existing, alias); err != nil { t.Fatal(err) }
 cases := []struct{ name, path, want string }{
  {"new sibling", filepath.Join(root,"new"), ""},
  {"new child", filepath.Join(existing,"new"), ""},
  {"existing directory", existing, "already exists"},
  {"existing file", file, "already exists"},
  {"missing parent", filepath.Join(root,"missing","new"), "restore parent"},
  {"file parent", filepath.Join(file,"new"), "not a directory"},
  {"symlink parent", filepath.Join(alias,"new"), "contains symlink"},
  {"root", string(filepath.Separator), "unsafe restore target"},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   err:=checkColdRestoreDestination(tc.path)
   if tc.want=="" { if err!=nil { t.Fatal(err) };return }
   if err==nil || !strings.Contains(err.Error(),tc.want) { t.Fatalf("got %v; want %q",err,tc.want) }
  })
 }
}

func TestColdRestoreDestinationRejectsCredentialIndependentInvalidTarget(t *testing.T) {
 root:=t.TempDir()
 active:=filepath.Join(root,"active")
 backup:=filepath.Join(root,"backup")
 for _,p:=range []string{active,backup} { if err:=os.Mkdir(p,0700);err!=nil {t.Fatal(err)} }
 err:=run([]string{"--operation","restore","--active-data",active,"--backup",backup,"--target",filepath.Join(root,"absent","child"),"--manifest",filepath.Join(root,"missing-manifest"),"--key-file",filepath.Join(root,"missing-key")},os.Stdout)
 if err==nil || !strings.Contains(err.Error(),"restore parent") { t.Fatalf("expected destination preflight before credential read; got %v",err) }
}

func TestColdRestoreValidDestinationStillRequiresCredentials(t *testing.T) {
 root := t.TempDir()
 active := filepath.Join(root, "active")
 backup := filepath.Join(root, "backup")
 for _, path := range []string{active, backup} {
  if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
 }
 err := run([]string{"--operation","restore","--active-data",active,"--backup",backup,"--target",filepath.Join(root,"new"),"--manifest",filepath.Join(root,"missing-manifest"),"--key-file",filepath.Join(root,"missing-key")},os.Stdout)
 if err == nil { t.Fatal("missing credentials must not permit restore") }
 if strings.Contains(err.Error(),"restore parent") || strings.Contains(err.Error(),"already exists") {
  t.Fatalf("valid destination incorrectly rejected: %v",err)
 }
 if _, statErr := os.Lstat(filepath.Join(root,"new")); !os.IsNotExist(statErr) {
  t.Fatalf("failed restore created destination: %v",statErr)
 }
}
