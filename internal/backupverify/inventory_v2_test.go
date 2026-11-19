package backupverify

import (
 "os"
 "path/filepath"
 "testing"
)

func TestVersion2PreservesEmptyDirectories(t *testing.T) {
 root := t.TempDir()
 if err := os.MkdirAll(filepath.Join(root,"mail","empty","nested"),0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(root,"mail","message"),[]byte("hello"),0600); err != nil { t.Fatal(err) }
 key := []byte("0123456789abcdef0123456789abcdef")
 signed, err := CreateSignedInventory(root,key)
 if err != nil { t.Fatal(err) }
 if signed.Manifest.Version != 2 || len(signed.Manifest.Directories) != 3 { t.Fatalf("unexpected directory inventory: %+v",signed.Manifest) }
 if _, err := VerifyComplete(root,signed,key); err != nil { t.Fatal(err) }
 target := filepath.Join(t.TempDir(),"restored")
 if _, err := RestoreCold(root,target,signed,key); err != nil { t.Fatal(err) }
 if st, err := os.Stat(filepath.Join(target,"mail","empty","nested")); err != nil || !st.IsDir() { t.Fatalf("missing restored empty directory: %v",err) }
 if _, err := VerifyComplete(target,signed,key); err != nil { t.Fatal(err) }
 if err := os.Mkdir(filepath.Join(target,"extra"),0700); err != nil { t.Fatal(err) }
 if _, err := VerifyComplete(target,signed,key); err == nil { t.Fatal("unlisted empty directory accepted") }
}

func TestVersion2DirectoryTamperingAndCollisions(t *testing.T) {
 root := t.TempDir()
 if err := os.MkdirAll(filepath.Join(root,"a","b"),0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(root,"a","mail"),[]byte("x"),0600); err != nil { t.Fatal(err) }
 m, err := BuildInventory(root)
 if err != nil { t.Fatal(err) }
 cases := []struct{name string; dirs []string}{
  {"missing parent",[]string{"a/b"}},
  {"duplicate",[]string{"a","a"}},
  {"traversal",[]string{"../escape"}},
  {"file collision",[]string{"a","a/mail"}},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T) { changed:=m; changed.Directories=tc.dirs; if err:=ValidateManifest(changed);err==nil { t.Fatal("invalid directories accepted") } })
 }
}
