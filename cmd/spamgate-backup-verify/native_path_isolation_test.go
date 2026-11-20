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
