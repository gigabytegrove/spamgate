//go:build linux

package backupverify

import (
 "errors"
 "os"
 "path/filepath"
 "syscall"
 "testing"
)

func TestPublishRestoreDoesNotReplaceExistingDirectory(t *testing.T) {
 parent:=t.TempDir()
 stage:=filepath.Join(parent,"stage")
 target:=filepath.Join(parent,"target")
 if err:=os.Mkdir(stage,0700);err!=nil {t.Fatal(err)}
 if err:=os.Mkdir(target,0700);err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(target,"sentinel"),[]byte("preserve"),0600);err!=nil {t.Fatal(err)}
 err:=publishRestore(stage,target)
 if !errors.Is(err,syscall.EEXIST) {t.Fatalf("expected EEXIST, got %v",err)}
 if b,err:=os.ReadFile(filepath.Join(target,"sentinel"));err!=nil || string(b)!="preserve" {t.Fatalf("target altered: %q %v",b,err)}
 if _,err:=os.Stat(stage);err!=nil {t.Fatalf("stage removed: %v",err)}
}

func TestPublishRestoreCreatesDestination(t *testing.T) {
 parent:=t.TempDir()
 stage:=filepath.Join(parent,"stage")
 target:=filepath.Join(parent,"target")
 if err:=os.Mkdir(stage,0700);err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(stage,"data"),[]byte("ok"),0600);err!=nil {t.Fatal(err)}
 if err:=publishRestore(stage,target);err!=nil {t.Fatal(err)}
 if b,err:=os.ReadFile(filepath.Join(target,"data"));err!=nil || string(b)!="ok" {t.Fatalf("published data: %q %v",b,err)}
 if _,err:=os.Stat(stage);!os.IsNotExist(err) {t.Fatalf("stage still present: %v",err)}
}
