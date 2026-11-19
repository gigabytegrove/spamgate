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

func TestRestoreColdNestedMultiFileInventory(t *testing.T) {
 root := t.TempDir()
 files := map[string]string{
  "db/mail.db": "mail database fixture",
  "queue/held/entry": "held queue fixture",
  "policies/tenant.json": "{\"enabled\":true}",
 }
 for name, body := range files {
  full := filepath.Join(root, filepath.FromSlash(name))
  if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil { t.Fatal(err) }
  if err := os.WriteFile(full, []byte(body), 0600); err != nil { t.Fatal(err) }
 }
 key := []byte("0123456789abcdef0123456789abcdef")
 signed, err := CreateSignedInventory(root, key)
 if err != nil { t.Fatal(err) }
 target := filepath.Join(t.TempDir(), "restored")
 report, err := RestoreCold(root, target, signed, key)
 if err != nil { t.Fatal(err) }
 if report.Files != len(files) { t.Fatalf("restored %d files, want %d", report.Files, len(files)) }
 if _, err := VerifyComplete(target, signed, key); err != nil { t.Fatalf("published inventory invalid: %v", err) }
 for name, body := range files {
  b, err := os.ReadFile(filepath.Join(target, filepath.FromSlash(name)))
  if err != nil || string(b) != body { t.Fatalf("%s: %q, %v", name, b, err) }
 }
}

func TestRestoreColdRejectsCorruptedSourceWithoutPublication(t *testing.T) {
 root, _ := fixture(t)
 key := []byte("0123456789abcdef0123456789abcdef")
 signed, err := CreateSignedInventory(root, key)
 if err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(root, "db", "mail.db"), []byte("changed"), 0600); err != nil { t.Fatal(err) }
 parent := t.TempDir()
 target := filepath.Join(parent, "restored")
 if _, err := RestoreCold(root, target, signed, key); err == nil { t.Fatal("corrupted source accepted") }
 if _, err := os.Lstat(target); !os.IsNotExist(err) { t.Fatalf("unexpected published target: %v", err) }
}
