package core

import (
 "context"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

func TestQuarantineRefusesUnsafeIDAndSymlinkDirectory(t *testing.T) {
 root:=t.TempDir()
 st,err:=Open(root);if err!=nil{t.Fatal(err)}
 if err:=st.Quarantine("../escape",[]byte("private"));err==nil{t.Fatal("accepted path traversal ID")}
 victim:=t.TempDir()
 link:=filepath.Join(root,"quarantine")
 if err:=os.Symlink(victim,link);err!=nil{t.Skipf("symlink unavailable: %v",err)}
 if err:=st.Quarantine(ID(),[]byte("private"));err==nil{t.Fatal("followed quarantine directory symlink")}
 files,err:=os.ReadDir(victim);if err!=nil{t.Fatal(err)}
 if len(files)!=0{t.Fatal("private message escaped to symlink target")}
 if err:=os.Remove(link);err!=nil{t.Fatal(err)}
 id:=ID()
 if err:=st.Quarantine(id,[]byte("Subject: test\r\n\r\noriginal"));err!=nil{t.Fatal(err)}
 data,err:=st.Quarantined(id);if err!=nil{t.Fatal(err)}
 if string(data)!="Subject: test\r\n\r\noriginal"{t.Fatal("quarantine original altered")}
 info,err:=os.Stat(filepath.Join(root,"quarantine",id+".eml"));if err!=nil{t.Fatal(err)}
 if info.Mode().Perm()!=0600{t.Fatalf("private original has mode %v",info.Mode().Perm())}
 if _,err:=st.Quarantined("../escape");err==nil||errors.Is(err,os.ErrNotExist){t.Fatal("unsafe read ID not rejected")}
}
func TestScannerInvalidMessageErrorClassification(t *testing.T) {
 st,err:=Open(t.TempDir());if err!=nil{t.Fatal(err)}
 scanner:=&Scanner{Store:st}
 for _,raw:=range [][]byte{nil,[]byte("not a header\r\n\r\nbody")} {
  _,err:=scanner.Scan(context.Background(),Input{Raw:raw,Connector:"smtp"})
  if !errors.Is(err,ErrInvalidMessage){t.Fatalf("expected invalid message sentinel, got %v",err)}
 }
}
