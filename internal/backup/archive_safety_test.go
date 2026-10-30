package backup

import (
 "archive/zip"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
)

func TestVerifyRefusesSymlinkArchive(t *testing.T) {
 root:=t.TempDir()
 source:=filepath.Join(root,"source")
 if err:=os.MkdirAll(source,0700);err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(source,"config.json"),[]byte("{}"),0600);err!=nil {t.Fatal(err)}
 archive:=filepath.Join(root,"snapshot.zip")
 if err:=Create(source,archive);err!=nil {t.Fatal(err)}
 alias:=filepath.Join(root,"alias.zip")
 if err:=os.Symlink(archive,alias);err!=nil {t.Skip(err)}
 if _,err:=Verify(alias);err==nil {t.Fatal("verified a symlink archive")}
 if err:=Restore(alias,filepath.Join(root,"restored"));err==nil {t.Fatal("restored from a symlink archive")}
}

func TestVerifyRefusesEmptyBackupManifest(t *testing.T) {
 root:=t.TempDir()
 archive:=filepath.Join(root,"empty.zip")
 f,err:=os.Create(archive);if err!=nil {t.Fatal(err)}
 z:=zip.NewWriter(f)
 w,err:=z.Create(manifestPath);if err!=nil {t.Fatal(err)}
 if err:=json.NewEncoder(w).Encode(Manifest{Format:1,Product:"SpamGate"});err!=nil {t.Fatal(err)}
 if err:=z.Close();err!=nil {t.Fatal(err)}
 if err:=f.Close();err!=nil {t.Fatal(err)}
 if _,err:=Verify(archive);err==nil {t.Fatal("accepted empty backup manifest")}
}
