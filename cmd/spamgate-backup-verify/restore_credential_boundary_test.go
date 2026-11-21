package main

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestRestoreCredentialBoundary(t *testing.T) {
 base := t.TempDir()
 secretDir := filepath.Join(base,"secrets")
 if err := os.Mkdir(secretDir,0700); err != nil { t.Fatal(err) }
 key := filepath.Join(secretDir,"key")
 manifest := filepath.Join(secretDir,"manifest")
 for _, path := range []string{key,manifest} {
  if err := os.WriteFile(path,[]byte("test credential"),0600); err != nil { t.Fatal(err) }
 }
 alias := filepath.Join(base,"secret-alias")
 if err := os.Symlink(secretDir,alias); err != nil { t.Fatal(err) }
 hardlink := filepath.Join(base,"key-hardlink")
 if err := os.Link(key,hardlink); err != nil { t.Fatal(err) }
 cases := []struct{name,target string; reject bool}{
  {"separate directory",filepath.Join(base,"restore"),false},
  {"separate nested directory",filepath.Join(base,"new","restore"),false},
  {"credential directory",secretDir,true},
  {"ancestor of credentials",base,true},
  {"symlink ancestor",alias,true},
  {"key itself",key,true},
  {"manifest itself",manifest,true},
  {"hardlinked key",hardlink,true},
 }
 for _, tc := range cases { t.Run(tc.name,func(t *testing.T){
  err := checkRestoreCredentialBoundary(tc.target,manifest,key)
  if tc.reject && err == nil { t.Fatal("expected credential overlap refusal") }
  if !tc.reject && err != nil { t.Fatal(err) }
 }) }
}

func TestRestoreCredentialBoundaryRejectsMissingAndNonregularInputs(t *testing.T) {
 base := t.TempDir()
 key := filepath.Join(base,"key")
 manifest := filepath.Join(base,"manifest")
 if err := os.WriteFile(key,[]byte("key"),0600); err != nil { t.Fatal(err) }
 target := filepath.Join(base,"restore")
 if err := checkRestoreCredentialBoundary(target,manifest,key); err == nil || !strings.Contains(err.Error(),"signed manifest") { t.Fatalf("missing manifest: %v",err) }
 if err := os.Mkdir(manifest,0700); err != nil { t.Fatal(err) }
 if err := checkRestoreCredentialBoundary(target,manifest,key); err == nil || !strings.Contains(err.Error(),"regular file") { t.Fatalf("directory manifest: %v",err) }
}

func TestRestoreCLIRejectsExistingDestinationBeforeManifestDecode(t *testing.T) {
 base := t.TempDir()
 backup := filepath.Join(base,"backup")
 secrets := filepath.Join(base,"secrets")
 active := filepath.Join(base,"active")
 for _, dir := range []string{backup,secrets,active} {
  if err := os.Mkdir(dir,0700); err != nil { t.Fatal(err) }
 }
 key := filepath.Join(secrets,"key")
 manifest := filepath.Join(secrets,"manifest")
 for _, path := range []string{key,manifest} {
  if err := os.WriteFile(path,[]byte("not a valid signed manifest"),0600); err != nil { t.Fatal(err) }
 }
 var output strings.Builder
 err := run([]string{"-operation","restore","-backup",backup,"-active-data",active,"-target",secrets,"-manifest",manifest,"-key-file",key},&output)
 if err == nil || !strings.Contains(err.Error(),"restore target already exists") { t.Fatalf("expected existing destination refusal before decode, got %v",err) }
 if output.Len()!=0 { t.Fatalf("unexpected output %q",output.String()) }
}
