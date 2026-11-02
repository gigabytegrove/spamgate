package backup

import (
 "archive/zip"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

const backupTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestPolicyBackupRejectsWorkerUnreadableState(t *testing.T) {
 cases := []struct{name, raw string; valid bool}{
  {"valid-empty", `{"initialized":true,"greylist":{},"rates":{}}`, true},
  {"valid-nonempty", `{"initialized":true,"greylist":{"`+backupTestKey+`":"2026-11-02T17:00:00Z"},"rates":{"`+backupTestKey+`":["2026-11-02T17:00:00Z"]}}`, true},
  {"legacy", `{"greylist":{},"rates":{}}`, true},
  {"bad-greylist-key", `{"initialized":true,"greylist":{"sender@example.com":"2026-11-02T17:00:00Z"},"rates":{}}`, false},
  {"uppercase-rate-key", `{"initialized":true,"greylist":{},"rates":{"`+strings.ToUpper(backupTestKey)+`":[]}}`, false},
  {"bad-greylist-time", `{"initialized":true,"greylist":{"`+backupTestKey+`":"yesterday"},"rates":{}}`, false},
  {"zero-greylist-time", `{"initialized":true,"greylist":{"`+backupTestKey+`":"0001-01-01T00:00:00Z"},"rates":{}}`, false},
  {"bad-rate-time", `{"initialized":true,"greylist":{},"rates":{"`+backupTestKey+`":["tomorrow"]}}`, false},
  {"zero-rate-time", `{"initialized":true,"greylist":{},"rates":{"`+backupTestKey+`":["0001-01-01T00:00:00Z"]}}`, false},
  {"null-rate-list", `{"initialized":true,"greylist":{},"rates":{"`+backupTestKey+`":null}}`, false},
  {"unknown-root-field", `{"initialized":true,"greylist":{},"rates":{},"bypass":true}`, false},
  {"nested-duplicate", `{"initialized":true,"greylist":{},"rates":{"`+backupTestKey+`":[],"`+backupTestKey+`":[]}}`, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   _, err := decodePolicyWitness(strings.NewReader(tc.raw))
   if (err == nil) != tc.valid { t.Fatalf("decode valid=%v: %v", tc.valid, err) }
   root := t.TempDir()
   source := filepath.Join(root,"data")
   if err := os.Mkdir(source,0700); err != nil { t.Fatal(err) }
   if err := os.WriteFile(filepath.Join(source,"config.json"),[]byte("{}"),0600); err != nil { t.Fatal(err) }
   if err := os.WriteFile(filepath.Join(source,"delivery-policy.json"),[]byte(tc.raw),0600); err != nil { t.Fatal(err) }
   if err := os.WriteFile(filepath.Join(source,backupPolicyMarkerPath),[]byte(backupPolicyMarkerText),0600); err != nil { t.Fatal(err) }
   archive := filepath.Join(root,"created.zip")
   err = Create(source,archive)
   if (err == nil) != tc.valid { t.Fatalf("Create valid=%v: %v",tc.valid,err) }
   if !tc.valid { if _,err := os.Lstat(archive); !os.IsNotExist(err) {t.Fatalf("invalid backup published: %v",err)} }
   forged := filepath.Join(root,"forged.zip")
   writePolicyStateArchive(t,forged,tc.raw)
   _,err = Verify(forged)
   if (err == nil) != tc.valid {t.Fatalf("Verify valid=%v: %v",tc.valid,err)}
   dest := filepath.Join(root,"restored")
   err = Restore(forged,dest)
   if (err == nil) != tc.valid {t.Fatalf("Restore valid=%v: %v",tc.valid,err)}
   if !tc.valid {if _,err := os.Lstat(dest); !os.IsNotExist(err) {t.Fatalf("invalid restore published: %v",err)}}
  })
 }
}

func writePolicyStateArchive(t *testing.T, archive, state string) {
 t.Helper()
 f,err := os.Create(archive); if err != nil {t.Fatal(err)}
 zw := zip.NewWriter(f)
 entries := map[string]string{"config.json":"{}","delivery-policy.json":state,backupPolicyMarkerPath:backupPolicyMarkerText}
 manifest := Manifest{Format:1,Product:"SpamGate",Created:time.Now().UTC()}
 for path,content := range entries {
  w,err := zw.Create(path); if err != nil {t.Fatal(err)}
  if _,err := w.Write([]byte(content)); err != nil {t.Fatal(err)}
  hash := sha256.Sum256([]byte(content))
  manifest.Entries = append(manifest.Entries,Entry{Path:path,Bytes:int64(len(content)),SHA256:hex.EncodeToString(hash[:])})
 }
 w,err := zw.Create(manifestPath); if err != nil {t.Fatal(err)}
 if err := json.NewEncoder(w).Encode(manifest); err != nil {t.Fatal(err)}
 if err := zw.Close(); err != nil {t.Fatal(err)}
 if err := f.Close(); err != nil {t.Fatal(err)}
}
