package backup

import (
 "os"
 "path/filepath"
 "testing"
)

func TestVerifyBackupSourcePathStable(t *testing.T) {
 p:=filepath.Join(t.TempDir(),"message.eml")
 if err:=os.WriteFile(p,[]byte("original"),0600);err!=nil {t.Fatal(err)}
 before,err:=os.Lstat(p);if err!=nil {t.Fatal(err)}
 if err:=verifyBackupSourcePath(p,before);err!=nil {t.Fatal(err)}
}

func TestVerifyBackupSourcePathReplacement(t *testing.T) {
 dir:=t.TempDir()
 p:=filepath.Join(dir,"message.eml")
 replacement:=filepath.Join(dir,"replacement")
 if err:=os.WriteFile(p,[]byte("original"),0600);err!=nil {t.Fatal(err)}
 before,err:=os.Lstat(p);if err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(replacement,[]byte("original"),0600);err!=nil {t.Fatal(err)}
 if err:=os.Rename(replacement,p);err!=nil {t.Fatal(err)}
 if err:=verifyBackupSourcePath(p,before);err==nil {t.Fatal("accepted replacement inode")}
}

func TestVerifyBackupSourcePathUnlinkAndSymlink(t *testing.T) {
 dir:=t.TempDir()
 p:=filepath.Join(dir,"message.eml")
 if err:=os.WriteFile(p,[]byte("original"),0600);err!=nil {t.Fatal(err)}
 before,err:=os.Lstat(p);if err!=nil {t.Fatal(err)}
 if err:=os.Remove(p);err!=nil {t.Fatal(err)}
 if err:=verifyBackupSourcePath(p,before);err==nil {t.Fatal("accepted unlinked source")}
 if err:=os.Symlink(filepath.Join(dir,"elsewhere"),p);err!=nil {t.Fatal(err)}
 if err:=verifyBackupSourcePath(p,before);err==nil {t.Fatal("accepted symlink substitution")}
}

func TestVerifyBackupSourcePathModified(t *testing.T) {
 p:=filepath.Join(t.TempDir(),"message.eml")
 if err:=os.WriteFile(p,[]byte("original"),0600);err!=nil {t.Fatal(err)}
 before,err:=os.Lstat(p);if err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(p,[]byte("modified-longer"),0600);err!=nil {t.Fatal(err)}
 if err:=verifyBackupSourcePath(p,before);err==nil {t.Fatal("accepted changed source")}
}
