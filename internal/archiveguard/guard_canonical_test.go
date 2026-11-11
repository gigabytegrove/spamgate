package archiveguard

import (
 "archive/zip"
 "bytes"
 "errors"
 "strings"
 "testing"
)

func TestRejectAmbiguousArchiveMembers(t *testing.T) {
 cases := []struct{name string; member string}{
  {"dot segment", "folder/./payload.txt"},
  {"parent segment", "folder/../payload.txt"},
  {"duplicate separator", "folder//payload.txt"},
  {"trailing dot", "folder/."},
  {"backslash separator", "folder\\payload.txt"},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   var b bytes.Buffer
   w := zip.NewWriter(&b)
   f, err := w.Create(tc.member)
   if err != nil { t.Fatal(err) }
   if _, err := f.Write([]byte("payload")); err != nil { t.Fatal(err) }
   if err := w.Close(); err != nil { t.Fatal(err) }
   _, err = Inspect(bytes.NewReader(b.Bytes()), int64(b.Len()), Limits{MaxFiles:10,MaxMemberBytes:1024,MaxTotalBytes:4096,MaxRatio:100})
   if !errors.Is(err, ErrUnsafe) { t.Fatalf("expected unsafe member for %q, got %v", tc.member, err) }
  })
 }
}

func TestRejectUnsupportedCompressionMethod(t *testing.T) {
 var b bytes.Buffer
 w := zip.NewWriter(&b)
 h := &zip.FileHeader{Name:"payload.bin", Method:zip.Store}
 f, err := w.CreateHeader(h)
 if err != nil { t.Fatal(err) }
 if _, err := f.Write([]byte("data")); err != nil { t.Fatal(err) }
 if err := w.Close(); err != nil { t.Fatal(err) }
 raw := b.Bytes()
 // Change both local-file and central-directory method fields.
 local := bytes.Index(raw, []byte{'P','K',3,4})
 central := bytes.Index(raw, []byte{'P','K',1,2})
 if local < 0 || central < 0 { t.Fatal("missing ZIP headers") }
 raw[local+8],raw[local+9] = 99,0
 raw[central+10],raw[central+11] = 99,0
 _, err = Inspect(bytes.NewReader(raw), int64(len(raw)), Limits{MaxFiles:10,MaxMemberBytes:1024,MaxTotalBytes:4096,MaxRatio:100})
 if !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(),"compression method") { t.Fatalf("expected unsupported method, got %v",err) }
}

func TestAcceptCanonicalDirectoryAndFile(t *testing.T) {
 var b bytes.Buffer
 w := zip.NewWriter(&b)
 if _,err:=w.Create("folder/");err!=nil {t.Fatal(err)}
 f,err:=w.Create("folder/payload.txt");if err!=nil {t.Fatal(err)}
 if _,err=f.Write([]byte("data"));err!=nil {t.Fatal(err)}
 if err=w.Close();err!=nil {t.Fatal(err)}
 report,err:=Inspect(bytes.NewReader(b.Bytes()),int64(b.Len()),Limits{MaxFiles:10,MaxMemberBytes:1024,MaxTotalBytes:4096,MaxRatio:100})
 if err!=nil {t.Fatal(err)}
 if report.Files!=1 || report.ReadBytes!=4 {t.Fatalf("unexpected report: %+v",report)}
}
