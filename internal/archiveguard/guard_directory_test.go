package archiveguard

import (
 "archive/zip"
 "bytes"
 "errors"
 "testing"
)

// Directory entries must retain a single trailing slash but otherwise be canonical.
func TestCanonicalDirectoryEntries(t *testing.T) {
 for _, tc := range []struct{name string; safe bool}{
  {"folder/",true},
  {"folder/sub/",true},
  {"folder//",false},
  {"folder/./",false},
  {"folder/../",false},
  {"../",false},
  {"/",false},
  {"./",false},
 } {
  t.Run(tc.name,func(t *testing.T){
   var b bytes.Buffer
   zw:=zip.NewWriter(&b)
   if _,err:=zw.Create(tc.name);err!=nil {t.Fatal(err)}
   if err:=zw.Close();err!=nil {t.Fatal(err)}
   result,err:=Inspect(bytes.NewReader(b.Bytes()),int64(b.Len()),limits())
   if tc.safe {
    if err!=nil || result.Files!=0 {t.Fatalf("directory rejected: report=%+v err=%v",result,err)}
   } else if !errors.Is(err,ErrUnsafe) {t.Fatalf("unsafe directory accepted: %v",err)}
  })
 }
}

func TestDirectoryFileNameCollision(t *testing.T) {
 var b bytes.Buffer
 zw:=zip.NewWriter(&b)
 if _,err:=zw.Create("same/");err!=nil {t.Fatal(err)}
 f,err:=zw.Create("same");if err!=nil {t.Fatal(err)}
 if _,err=f.Write([]byte("data"));err!=nil {t.Fatal(err)}
 if err=zw.Close();err!=nil {t.Fatal(err)}
 _,err=Inspect(bytes.NewReader(b.Bytes()),int64(b.Len()),limits())
 if !errors.Is(err,ErrUnsafe) {t.Fatalf("expected directory/file collision rejection: %v",err)}
}
