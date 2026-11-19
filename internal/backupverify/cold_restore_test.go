package backupverify

import (
 "os"
 "path/filepath"
 "testing"
)

func TestRestoreColdPublishesVerifiedTree(t *testing.T) {
 root,_:=fixture(t)
 key:=[]byte("0123456789abcdef0123456789abcdef")
 signed,err:=CreateSignedInventory(root,key)
 if err!=nil { t.Fatal(err) }
 target:=filepath.Join(t.TempDir(),"restored")
 report,err:=RestoreCold(root,target,signed,key)
 if err!=nil { t.Fatal(err) }
 if report.Files!=1 { t.Fatalf("report: %+v",report) }
 data,err:=os.ReadFile(filepath.Join(target,"db","mail.db"))
 if err!=nil || len(data)==0 { t.Fatalf("restored data: %q %v",data,err) }
 if _,err:=RestoreCold(root,target,signed,key);err==nil { t.Fatal("existing target overwritten") }
}

func TestRestoreColdRejectsTamperAndLeavesNoTarget(t *testing.T) {
 root,_:=fixture(t)
 key:=[]byte("0123456789abcdef0123456789abcdef")
 signed,err:=CreateSignedInventory(root,key)
 if err!=nil { t.Fatal(err) }
 target:=filepath.Join(t.TempDir(),"restored")
 signed.MAC="0000000000000000000000000000000000000000000000000000000000000000"
 if _,err:=RestoreCold(root,target,signed,key);err==nil { t.Fatal("tampered manifest accepted") }
 if _,err:=os.Lstat(target);!os.IsNotExist(err) { t.Fatalf("target exists: %v",err) }
}

func TestRestoreColdRefusesBackupOverlap(t *testing.T) {
 root,_:=fixture(t)
 key:=[]byte("0123456789abcdef0123456789abcdef")
 signed,err:=CreateSignedInventory(root,key)
 if err!=nil { t.Fatal(err) }
 if _,err:=RestoreCold(root,filepath.Join(root,"new"),signed,key);err==nil { t.Fatal("nested target accepted") }
}

func TestRestoreColdRefusesSymlinkParent(t *testing.T) {
 root,_:=fixture(t)
 key:=[]byte("0123456789abcdef0123456789abcdef")
 signed,err:=CreateSignedInventory(root,key)
 if err!=nil { t.Fatal(err) }
 parent:=t.TempDir()
 link:=filepath.Join(t.TempDir(),"link")
 if err:=os.Symlink(parent,link);err!=nil { t.Skip(err) }
 if _,err:=RestoreCold(root,filepath.Join(link,"restored"),signed,key);err==nil { t.Fatal("symlink parent accepted") }
}
