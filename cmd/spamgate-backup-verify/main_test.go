package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/backupverify"
)

func TestNativeBackupCLI(t *testing.T) {
 base := t.TempDir()
 active := filepath.Join(base,"active")
 backup := filepath.Join(base,"backup")
 if err:=os.Mkdir(active,0700);err!=nil{t.Fatal(err)}
 if err:=os.MkdirAll(filepath.Join(backup,"empty","nested"),0700);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(backup,"message.db"),[]byte("durable"),0600);err!=nil{t.Fatal(err)}
 key:=bytes.Repeat([]byte{0x42},32)
 keyFile:=filepath.Join(base,"key")
 if err:=os.WriteFile(keyFile,key,0600);err!=nil{t.Fatal(err)}
 signed,err:=backupverify.CreateSignedInventory(backup,key)
 if err!=nil{t.Fatal(err)}

 manifest:=filepath.Join(base,"manifest.json")
 if err:=writeManifest(manifest,signed);err!=nil{t.Fatal(err)}
 args:=[]string{"-backup",backup,"-manifest",manifest,"-key-file",keyFile,"-active-data",active}
 var out bytes.Buffer
 if err:=run(args,&out);err!=nil{t.Fatal(err)}
 if !strings.Contains(out.String(),"verify successful"){t.Fatal(out.String())}
 target:=filepath.Join(base,"restored")
 if err:=run(append(append([]string{},args...),"-operation","restore","-target",target),&out);err!=nil{t.Fatal(err)}
 if _,err:=os.Stat(filepath.Join(target,"empty","nested"));err!=nil{t.Fatal(err)}
 if err:=run(append(append([]string{},args...),"-operation","restore","-target",active),&out);err==nil{t.Fatal("active data restore accepted")}
 if err:=os.Chmod(keyFile,0644);err!=nil{t.Fatal(err)}
 if err:=run(args,&out);err==nil{t.Fatal("world-readable key accepted")}
}

func writeManifest(path string, signed backupverify.SignedManifest) error {
 data,err:=json.Marshal(signed)
 if err!=nil{return err}
 return os.WriteFile(path,data,0600)
}

func TestPathOverlap(t *testing.T) {
 if !containsPath("/srv/data","/srv/data/a"){t.Fatal("nested single-character path not detected")}
 if containsPath("/srv/data","/srv/database"){t.Fatal("sibling mistaken for child")}
 if containsPath("/srv/data","/srv/data"){t.Fatal("same path mistaken for child")}
}
