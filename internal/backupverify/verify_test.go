package backupverify

import (
 "crypto/sha256"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func fixture(t *testing.T)(string,Manifest){
 t.Helper()
 root:=t.TempDir()
 if err:=os.Mkdir(filepath.Join(root,"db"),0700);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(root,"db","mail.db"),[]byte("durable"),0600);err!=nil{t.Fatal(err)}
 digest:=sha256.Sum256([]byte("durable"))
 return root,Manifest{Version:1,Files:[]Entry{{Path:"db/mail.db",Size:7,SHA256:fmt.Sprintf("%x",digest)}}}
}
func TestVerifyGoodAndCorruption(t *testing.T){
 root,m:=fixture(t)
 report,err:=Verify(root,m)
 if err!=nil || report.Files!=1 || report.Bytes!=7{t.Fatalf("%+v %v",report,err)}
 if err:=os.WriteFile(filepath.Join(root,"db","mail.db"),[]byte("changed"),0600);err!=nil{t.Fatal(err)}
 if _,err:=Verify(root,m);err==nil{t.Fatal("corruption accepted")}
}
func TestRejectUnsafeManifest(t *testing.T){
 _,m:=fixture(t)
 for _,bad:=range []string{"../escape","/etc/passwd","db/../mail.db","db//mail.db","db\\mail.db","C:foo","."}{
  t.Run(bad,func(t *testing.T){
   copy:=m;copy.Files=append([]Entry(nil),m.Files...);copy.Files[0].Path=bad
   if err:=ValidateManifest(copy);err==nil{t.Fatal("unsafe path accepted")}
  })
 }
 copy:=m;copy.Files=append(copy.Files,copy.Files[0])
 if err:=ValidateManifest(copy);err==nil{t.Fatal("duplicate accepted")}
 copy=m;copy.Files=append([]Entry(nil),m.Files...);copy.Files=append(copy.Files,Entry{Path:"db",Size:1,SHA256:m.Files[0].SHA256})
 if err:=ValidateManifest(copy);err==nil{t.Fatal("file/directory collision accepted")}
 copy=m;copy.Files=append([]Entry(nil),m.Files...);copy.Files[0].SHA256=strings.Repeat("A",64)
 if err:=ValidateManifest(copy);err==nil{t.Fatal("uppercase digest accepted")}
}
func TestRejectSymlinkAndMissingFiles(t *testing.T){
 root,m:=fixture(t)
 if err:=os.Remove(filepath.Join(root,"db","mail.db"));err!=nil{t.Fatal(err)}
 if _,err:=Verify(root,m);err==nil{t.Fatal("missing file accepted")}
 if err:=os.Symlink("/etc/passwd",filepath.Join(root,"db","mail.db"));err!=nil{t.Skip(err)}
 if _,err:=Verify(root,m);err==nil{t.Fatal("symlink accepted")}
}
func TestRejectParentSymlink(t *testing.T){
 root,m:=fixture(t)
 if err:=os.Rename(filepath.Join(root,"db"),filepath.Join(root,"real"));err!=nil{t.Fatal(err)}
 if err:=os.Symlink("real",filepath.Join(root,"db"));err!=nil{t.Skip(err)}
 if _,err:=Verify(root,m);err==nil{t.Fatal("parent symlink accepted")}
}
