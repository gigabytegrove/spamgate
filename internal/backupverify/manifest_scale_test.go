package backupverify

import (
 "crypto/sha256"
 "fmt"
 "testing"
)

// Large inventories must not incur a quadratic directory lookup for each file.
func TestValidateLargeVersion2Inventory(t *testing.T) {
 const count = 12000
 digest := fmt.Sprintf("%x", sha256.Sum256([]byte("x")))
 m := Manifest{Version:2, Directories:[]string{"mail"}, Files:make([]Entry,0,count)}
 for i:=0;i<count;i++ {
  m.Files=append(m.Files,Entry{Path:fmt.Sprintf("mail/%05d.eml",i),Size:1,SHA256:digest})
 }
 if err:=ValidateManifest(m);err!=nil { t.Fatal(err) }
 m.Files[count-1].Path="missing/message.eml"
 if err:=ValidateManifest(m);err==nil { t.Fatal("unlisted parent accepted") }
 m.Files[count-1].Path="mail"
 if err:=ValidateManifest(m);err==nil { t.Fatal("directory/file collision accepted") }
}
