package spoolaudit

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestVerifyRecordPathStable(t *testing.T) {
 dir:=t.TempDir()
 path:=filepath.Join(dir,"record.json")
 if err:=os.WriteFile(path,[]byte("original"),0600);err!=nil {t.Fatal(err)}
 f,err:=os.Open(path);if err!=nil {t.Fatal(err)}
 defer f.Close()
 opened,err:=f.Stat();if err!=nil {t.Fatal(err)}
 if err:=verifyRecordPathStable(path,opened);err!=nil {t.Fatalf("stable file: %v",err)}
 if err:=os.Rename(path,path+".old");err!=nil {t.Fatal(err)}
 if err:=verifyRecordPathStable(path,opened);err==nil||!strings.Contains(err.Error(),"disappeared") {
  t.Fatalf("detached inode accepted: %v",err)
 }
 if err:=os.WriteFile(path,[]byte("original"),0600);err!=nil {t.Fatal(err)}
 if err:=verifyRecordPathStable(path,opened);err==nil||!strings.Contains(err.Error(),"replaced") {
  t.Fatalf("replacement inode accepted: %v",err)
 }
 if err:=os.Remove(path);err!=nil {t.Fatal(err)}
 if err:=os.Symlink(path+".old",path);err!=nil {t.Fatal(err)}
 if err:=verifyRecordPathStable(path,opened);err==nil||!strings.Contains(err.Error(),"replaced") {
  t.Fatalf("symlink substitution accepted: %v",err)
 }
}

func TestVerifyRecordPathStableDetectsLateAppend(t *testing.T) {
 dir:=t.TempDir();path:=filepath.Join(dir,"record.json")
 if err:=os.WriteFile(path,[]byte("original"),0600);err!=nil {t.Fatal(err)}
 f,err:=os.Open(path);if err!=nil {t.Fatal(err)};defer f.Close()
 opened,err:=f.Stat();if err!=nil {t.Fatal(err)}
 w,err:=os.OpenFile(path,os.O_APPEND|os.O_WRONLY,0);if err!=nil {t.Fatal(err)}
 if _,err:=w.Write([]byte("extra"));err!=nil {t.Fatal(err)}
 if err:=w.Close();err!=nil {t.Fatal(err)}
 if err:=verifyRecordPathStable(path,opened);err==nil||!strings.Contains(err.Error(),"metadata") {
  t.Fatalf("late append accepted: %v",err)
 }
}
