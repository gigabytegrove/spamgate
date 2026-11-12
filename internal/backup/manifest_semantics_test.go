package backup

import (
 "archive/zip"
 "crypto/sha256"
 "encoding/hex"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

// These fixtures contain valid payload bytes and matching digests. Only the
// manifest evidence is forged; verification must fail before publication.
func TestManifestSemanticIntegrityBlocksRestore(t *testing.T) {
 payload := []byte("persistent state\n")
 sum := sha256.Sum256(payload)
 digest := hex.EncodeToString(sum[:])
 base := func(created, sha string) string {
  return fmt.Sprintf(`{"format":1,"created":%q,"product":"SpamGate","entries":[{"path":"state.json","bytes":%d,"sha256":%q}]}`, created, len(payload), sha)
 }
 cases := []struct{name, created, digest string}{
  {"zero timestamp","0001-01-01T00:00:00Z",digest},
  {"pre product timestamp","1999-12-31T23:59:59Z",digest},
  {"future timestamp",time.Now().UTC().Add(72*time.Hour).Format(time.RFC3339),digest},
  {"uppercase digest","2026-11-01T00:00:00Z",strings.ToUpper(digest)},
  {"nonhex digest","2026-11-01T00:00:00Z",strings.Repeat("g",64)},
  {"short digest","2026-11-01T00:00:00Z",digest[:63]},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   dir := t.TempDir()
   archive := filepath.Join(dir,"forged.zip")
   f,err:=os.Create(archive);if err!=nil{t.Fatal(err)}
   z:=zip.NewWriter(f)
   for _, entry:=range []struct{name string; body []byte}{
    {"state.json",payload},
    {manifestPath,[]byte(base(tc.created,tc.digest))},
   } {
    w,err:=z.Create(entry.name);if err!=nil{t.Fatal(err)}
    if _,err=w.Write(entry.body);err!=nil{t.Fatal(err)}
   }
   if err:=z.Close();err!=nil{t.Fatal(err)}
   if err:=f.Close();err!=nil{t.Fatal(err)}
   if _,err:=Verify(archive);err==nil{t.Fatal("forged manifest passed verification")}
   destination:=filepath.Join(dir,"data")
   if err:=Restore(archive,destination);err==nil{t.Fatal("forged manifest restored")}
   if _,err:=os.Lstat(destination);!os.IsNotExist(err){t.Fatalf("restore destination published: %v",err)}
  })
 }
}

func TestManifestSemanticIntegrityAcceptsCanonicalEvidence(t *testing.T) {
 digest:=strings.Repeat("a",64)
 m:=Manifest{Created:time.Date(2026,11,1,0,0,0,0,time.UTC),Entries:[]Entry{{Path:"state.json",SHA256:digest}}}
 if err:=validateManifestSemantics(m);err!=nil{t.Fatal(err)}
}
