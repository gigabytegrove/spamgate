package archiveguard

import (
 "archive/zip"
 "bytes"
 "errors"
 "strings"
 "testing"
)
func fixture(t *testing.T, entries map[string]string) []byte {
 t.Helper()
 var b bytes.Buffer
 z := zip.NewWriter(&b)
 for name, data := range entries {
  w, err := z.Create(name); if err != nil { t.Fatal(err) }
  if _, err := w.Write([]byte(data)); err != nil { t.Fatal(err) }
 }
 if err := z.Close(); err != nil { t.Fatal(err) }
 return b.Bytes()
}
func limits() Limits { return Limits{MaxFiles:3,MaxMemberBytes:1024,MaxTotalBytes:2048,MaxRatio:1000} }
func TestInspectValid(t *testing.T) {
 b := fixture(t,map[string]string{"docs/readme.txt":"hello","archive.zip":"nested"})
 r, err := Inspect(bytes.NewReader(b),int64(len(b)),limits())
 if err != nil || r.Files != 2 || r.ReadBytes != 11 || r.NestedArchives != 1 { t.Fatalf("report=%+v err=%v",r,err) }
}
func TestMemberCount(t *testing.T) {
 b := fixture(t,map[string]string{"a":"a","b":"b"})
 l:=limits();l.MaxFiles=1
 _,err:=Inspect(bytes.NewReader(b),int64(len(b)),l)
 if !errors.Is(err,ErrLimit) { t.Fatal(err) }
}
func TestTraversal(t *testing.T) {
 for _,name:=range []string{"../secret","/absolute","C:/windows","a\\..\\..\\secret"} {
  b:=fixture(t,map[string]string{name:"x"})
  _,err:=Inspect(bytes.NewReader(b),int64(len(b)),limits())
  if !errors.Is(err,ErrUnsafe) { t.Fatalf("%q: %v",name,err) }
 }
}
func TestExpansionAndTotalLimits(t *testing.T) {
 b:=fixture(t,map[string]string{"large.txt":strings.Repeat("X",512)})
 l:=limits();l.MaxMemberBytes=100
 _,err:=Inspect(bytes.NewReader(b),int64(len(b)),l)
 if !errors.Is(err,ErrLimit) { t.Fatal(err) }
 l=limits();l.MaxTotalBytes=100
 _,err=Inspect(bytes.NewReader(b),int64(len(b)),l)
 if !errors.Is(err,ErrLimit) { t.Fatal(err) }
 l=limits();l.MaxRatio=2
 _,err=Inspect(bytes.NewReader(b),int64(len(b)),l)
 if !errors.Is(err,ErrLimit) { t.Fatal(err) }
}
func TestInvalidInputs(t *testing.T) {
 b:=fixture(t,map[string]string{"a":"x"})
 for _,tc:=range []struct{size int64;l Limits}{{-1,limits()},{int64(len(b)),Limits{}}} {
  if _,err:=Inspect(bytes.NewReader(b),tc.size,tc.l);err==nil { t.Fatal("expected error") }
 }
 if _,err:=Inspect(bytes.NewReader([]byte("not zip")),7,limits());err==nil {t.Fatal("expected invalid ZIP")}
}
