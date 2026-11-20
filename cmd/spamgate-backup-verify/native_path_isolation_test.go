package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestNativeBackupKeyIsolation(t *testing.T) {
 base := t.TempDir()
 active := filepath.Join(base,"active")
 backup := filepath.Join(base,"backup")
 for _,p := range []string{active,backup} { if err:=os.Mkdir(p,0700);err!=nil{t.Fatal(err)} }
 manifest := filepath.Join(base,"manifest")
 externalKey := filepath.Join(base,"key")
 for _,p := range []string{manifest,externalKey} { if err:=os.WriteFile(p,[]byte("test"),0600);err!=nil{t.Fatal(err)} }
 if err:=checkNativeBackupPaths(active,backup,externalKey,manifest);err!=nil{t.Fatal(err)}
 nested:=filepath.Join(backup,"key")
 if err:=os.WriteFile(nested,[]byte("test"),0600);err!=nil{t.Fatal(err)}
 if err:=checkNativeBackupPaths(active,backup,nested,manifest);err==nil || !strings.Contains(err.Error(),"outside backup"){t.Fatalf("nested key accepted: %v",err)}
 alias:=filepath.Join(base,"key-alias")
 if err:=os.Symlink(nested,alias);err!=nil{t.Fatal(err)}
 if err:=checkNativeBackupPaths(active,backup,alias,manifest);err==nil || !strings.Contains(err.Error(),"outside backup"){t.Fatalf("symlinked key accepted: %v",err)}
 activeKey:=filepath.Join(active,"key")
 if err:=os.WriteFile(activeKey,[]byte("test"),0600);err!=nil{t.Fatal(err)}
 if err:=checkNativeBackupPaths(active,backup,activeKey,manifest);err==nil || !strings.Contains(err.Error(),"outside active"){t.Fatalf("active key accepted: %v",err)}
 if err:=checkNativeBackupPaths(active,backup,manifest,manifest);err==nil || !strings.Contains(err.Error(),"separate"){t.Fatalf("same manifest and key accepted: %v",err)}
}

func TestNativeBackupPathBoundaryRejectsAlias(t *testing.T) {
 base:=t.TempDir()
 active:=filepath.Join(base,"active")
 backup:=filepath.Join(base,"backup")
 if err:=os.Mkdir(active,0700);err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(backup,0700);err!=nil{t.Fatal(err)}
 key:=filepath.Join(base,"key")
 manifest:=filepath.Join(base,"manifest")
 for _,p:=range []string{key,manifest} {if err:=os.WriteFile(p,[]byte("test"),0600);err!=nil{t.Fatal(err)}}
 alias:=filepath.Join(base,"backup-alias")
 if err:=os.Symlink(backup,alias);err!=nil{t.Fatal(err)}
 if err:=checkNativeBackupPaths(active,alias,key,manifest);err!=nil{t.Fatal(err)}
 if err:=checkNativeBackupPaths(active,backup,filepath.Join(base,"missing-key"),manifest);err==nil{t.Fatal("missing key accepted")}
}

func TestNativeBackupRejectsHardlinkedKeyAndManifest(t *testing.T) {
 base := t.TempDir()
 active := filepath.Join(base, "active")
 backup := filepath.Join(base, "backup")
 for _, dir := range []string{active, backup} {
  if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
 }
 key := filepath.Join(base, "secret.key")
 manifest := filepath.Join(base, "manifest.json")
 if err := os.WriteFile(key, []byte("not a real key"), 0600); err != nil { t.Fatal(err) }
 if err := os.Link(key, manifest); err != nil { t.Skipf("hard links unsupported: %v", err) }
 err := checkNativeBackupPaths(active, backup, key, manifest)
 if err == nil || !(strings.Contains(err.Error(), "separate files") || strings.Contains(err.Error(), "exactly one hard link")) {
  t.Fatalf("hardlinked key and manifest accepted: %v", err)
 }
 // A distinct inode is permitted; the verifier still checks signature and format.
 if err := os.Remove(manifest); err != nil { t.Fatal(err) }
 if err := os.WriteFile(manifest, []byte("not a real manifest"), 0600); err != nil { t.Fatal(err) }
 if err := checkNativeBackupPaths(active, backup, key, manifest); err != nil {
  t.Fatalf("distinct files rejected: %v", err)
 }
}

func TestNativeBackupRejectsKeyHardlinkedIntoBackup(t *testing.T) {
 base := t.TempDir()
 active := filepath.Join(base, "active")
 backup := filepath.Join(base, "backup")
 for _, dir := range []string{active, backup} {
  if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
 }
 key := filepath.Join(base, "secret.key")
 manifest := filepath.Join(base, "manifest.json")
 if err := os.WriteFile(key, []byte("secret"), 0600); err != nil { t.Fatal(err) }
 if err := os.WriteFile(manifest, []byte("manifest"), 0600); err != nil { t.Fatal(err) }
 if err := os.Link(key, filepath.Join(backup, "innocent-looking-file")); err != nil {
  t.Skipf("hard links unsupported: %v", err)
 }
 err := checkNativeBackupPaths(active, backup, key, manifest)
 if err == nil || !strings.Contains(err.Error(), "exactly one hard link") {
  t.Fatalf("backup hardlink of authentication key accepted: %v", err)
 }
}
