//go:build linux

package backup

import (
 "archive/zip"
 "errors"
 "os"
 "path/filepath"
 "syscall"
 "testing"
)

func TestBackupRefusesActiveWorkerLock(t *testing.T) {
 root := t.TempDir()
 data := filepath.Join(root, "data")
 if err := os.MkdirAll(data,0700);err!=nil {t.Fatal(err)}
 if err := os.WriteFile(filepath.Join(data,"config.json"),[]byte("{}"),0600);err!=nil {t.Fatal(err)}
 lock,err:=os.OpenFile(filepath.Join(data,".worker.lock"),os.O_CREATE|os.O_RDWR,0600)
 if err!=nil {t.Fatal(err)}
 defer lock.Close()
 if err:=syscall.Flock(int(lock.Fd()),syscall.LOCK_EX|syscall.LOCK_NB);err!=nil {t.Fatal(err)}
 archive:=filepath.Join(root,"snapshot.zip")
 if err:=Create(data,archive);err==nil {t.Fatal("backup succeeded while worker lock was held")}
 if _,err:=os.Stat(archive);!errors.Is(err,os.ErrNotExist) {t.Fatalf("unexpected backup publication: %v",err)}
 if err:=syscall.Flock(int(lock.Fd()),syscall.LOCK_UN);err!=nil {t.Fatal(err)}
 if err:=Create(data,archive);err!=nil {t.Fatal(err)}
 z,err:=zip.OpenReader(archive);if err!=nil {t.Fatal(err)}
 defer z.Close()
 for _,f:=range z.File {if f.Name==".worker.lock" {t.Fatal("runtime lock was included in backup")}}
 if _,err:=Verify(archive);err!=nil {t.Fatal(err)}
}

func TestBackupRefusesSymlinkWorkerLock(t *testing.T) {
 root:=t.TempDir()
 data:=filepath.Join(root,"data")
 if err:=os.MkdirAll(data,0700);err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(data,"config.json"),[]byte("{}"),0600);err!=nil {t.Fatal(err)}
 if err:=os.Symlink(filepath.Join(root,"outside"),filepath.Join(data,".worker.lock"));err!=nil {t.Skip(err)}
 if err:=Create(data,filepath.Join(root,"snapshot.zip"));err==nil {t.Fatal("accepted symlink lock")}
}
