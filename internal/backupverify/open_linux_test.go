//go:build linux

package backupverify

import (
 "os"
 "path/filepath"
 "syscall"
 "testing"
)

func TestOpenedDescriptorRejectsParentSymlink(t *testing.T) {
 root,m:=fixture(t)
 if err:=os.Rename(filepath.Join(root,"db"),filepath.Join(root,"real"));err!=nil{t.Fatal(err)}
 if err:=os.Symlink("real",filepath.Join(root,"db"));err!=nil{t.Fatal(err)}
 if _,err:=openVerifiedPath(root,m.Files[0].Path);err==nil{t.Fatal("followed parent symlink")}
}

func TestOpenedDescriptorRejectsFinalSymlinkAndDirectory(t *testing.T) {
 root,m:=fixture(t)
 target:=filepath.Join(root,"db","mail.db")
 if err:=os.Remove(target);err!=nil{t.Fatal(err)}
 if err:=os.Symlink("/etc/passwd",target);err!=nil{t.Fatal(err)}
 if _,err:=openVerifiedPath(root,m.Files[0].Path);err==nil{t.Fatal("followed final symlink")}
 if err:=os.Remove(target);err!=nil{t.Fatal(err)}
 if err:=os.Mkdir(target,0700);err!=nil{t.Fatal(err)}
 if _,err:=openVerifiedPath(root,m.Files[0].Path);err==nil{t.Fatal("accepted directory as file")}
}

func TestOpenedDescriptorPinsOriginalInode(t *testing.T) {
 root,m:=fixture(t)
 f,err:=openVerifiedPath(root,m.Files[0].Path)
 if err!=nil{t.Fatal(err)}
 defer f.Close()
 target:=filepath.Join(root,"db","mail.db")
 if err:=os.Rename(target,target+".old");err!=nil{t.Fatal(err)}
 if err:=os.Symlink("/etc/passwd",target);err!=nil{t.Fatal(err)}
 b:=make([]byte,7)
 if n,err:=f.Read(b);err!=nil || n!=7 || string(b)!="durable"{t.Fatalf("descriptor switched: %q %v",b,err)}
 if _,err:=openVerifiedPath(root,m.Files[0].Path);err==nil{t.Fatal("new symlink accepted")}
}

func TestOpenedDescriptorRejectsFIFOWithoutBlocking(t *testing.T) {
 root,m:=fixture(t)
 target:=filepath.Join(root,"db","mail.db")
 if err:=os.Remove(target);err!=nil{t.Fatal(err)}
 if err:=syscall.Mkfifo(target,0600);err!=nil{t.Fatal(err)}
 if _,err:=openVerifiedPath(root,m.Files[0].Path);err==nil{t.Fatal("accepted fifo")}
}
