//go:build linux

package backup

import (
 "os"
 "path/filepath"
 "syscall"
 "testing"
 "time"
)

func TestBackupSourceOpenRejectsSymlink(t *testing.T) {
 dir:=t.TempDir()
 target:=filepath.Join(dir,"target")
 link:=filepath.Join(dir,"link")
 if err:=os.WriteFile(target,[]byte("mail"),0600);err!=nil {t.Fatal(err)}
 if err:=os.Symlink(target,link);err!=nil {t.Fatal(err)}
 f,err:=openBackupSourceFile(link)
 if f!=nil {f.Close();t.Fatal("followed symlink")}
 if err==nil {t.Fatal("symlink accepted")}
}

func TestBackupSourceOpenFIFOIsNonblocking(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"fifo")
 if err:=syscall.Mkfifo(path,0600);err!=nil {t.Fatal(err)}
 done:=make(chan error,1)
 go func(){f,err:=openBackupSourceFile(path);if f!=nil {f.Close()};done<-err}()
 select {
 case <-done:
 case <-time.After(2*time.Second):t.Fatal("FIFO open blocked")
 }
}

func TestBackupSourceOpenRegularFile(t *testing.T) {
 path:=filepath.Join(t.TempDir(),"message")
 if err:=os.WriteFile(path,[]byte("mail"),0600);err!=nil {t.Fatal(err)}
 f,err:=openBackupSourceFile(path)
 if err!=nil {t.Fatal(err)}
 defer f.Close()
 info,err:=f.Stat()
 if err!=nil||!info.Mode().IsRegular(){t.Fatalf("not regular: %v %v",info,err)}
 buf:=make([]byte,4)
 n,err:=f.Read(buf)
 if err!=nil||n!=4||string(buf)!="mail"{t.Fatalf("read n=%d err=%v data=%q",n,err,buf)}
}
