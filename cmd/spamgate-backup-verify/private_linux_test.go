//go:build linux

package main

import (
 "bytes"
 "os"
 "path/filepath"
 "testing"
)

func TestPrivateInputSecurity(t *testing.T) {
 dir := t.TempDir()
 good := filepath.Join(dir, "good")
 payload := bytes.Repeat([]byte("k"), 32)
 if err := os.WriteFile(good, payload, 0600); err != nil { t.Fatal(err) }
 got, err := readPrivateFile(good, 64, 32)
 if err != nil || !bytes.Equal(got, payload) { t.Fatalf("valid private input: %v", err) }
 tests := []struct {name string; setup func(string) error}{
  {"symlink", func(p string) error {return os.Symlink(good,p)}},
  {"hardlink", func(p string) error {return os.Link(good,p)}},
  {"directory", func(p string) error {return os.Mkdir(p,0700)}},
  {"world-readable", func(p string) error {return os.WriteFile(p,payload,0644)}},
  {"too-large", func(p string) error {return os.WriteFile(p,bytes.Repeat([]byte("x"),65),0600)}},
  {"too-small", func(p string) error {return os.WriteFile(p,[]byte("short"),0600)}},
 }
 for _, tt := range tests {
  t.Run(tt.name,func(t *testing.T) {
   p:=filepath.Join(dir,tt.name)
   if err:=tt.setup(p);err!=nil{t.Fatal(err)}
   if _,err:=readPrivateFile(p,64,32);err==nil{t.Fatal("unsafe input accepted")}
  })
 }
}

func TestNativeCLIFailsClosedForManifestSymlink(t *testing.T) {
 dir:=t.TempDir()
 source:=filepath.Join(dir,"source")
 link:=filepath.Join(dir,"link")
 if err:=os.WriteFile(source,[]byte("{}"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(source,link);err!=nil{t.Fatal(err)}
 if _,err:=readPrivateFile(link,16<<20,1);err==nil{t.Fatal("symlink manifest accepted")}
}
