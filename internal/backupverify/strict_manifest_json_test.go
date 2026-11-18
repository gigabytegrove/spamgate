package backupverify

import (
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)

func TestSignedManifestRejectsDuplicateJSONKeysAtEveryLevel(t *testing.T) {
 _,m:=fixture(t)
 signed,err:=SignManifest(m,bytes.Repeat([]byte{0x42},32))
 if err!=nil {t.Fatal(err)}
 raw,err:=json.Marshal(signed)
 if err!=nil {t.Fatal(err)}
 base:=string(raw)
 cases:=map[string]string{
  "top level":strings.Replace(base,"\"manifest\":","\"manifest\":null,\"manifest\":",1),
  "manifest":strings.Replace(base,"\"version\":1","\"version\":1,\"version\":1",1),
  "file":strings.Replace(base,"\"size\":7","\"size\":7,\"size\":7",1),
  "authenticator":strings.Replace(base,"\"hmac_sha256\":","\"hmac_sha256\":\"bad\",\"hmac_sha256\":",1),
 }
 for name,input:=range cases {
  t.Run(name,func(t *testing.T){
   if input==base {t.Fatal("test fixture did not modify input")}
   if _,err:=DecodeSignedManifest(strings.NewReader(input));err==nil {t.Fatal("duplicate key accepted")}
  })
 }
}

func TestSignedManifestJSONSizeBoundary(t *testing.T) {
 // A valid manifest with excessive trailing whitespace must not bypass the
 // size limit, even though JSON permits arbitrary whitespace.
 _,m:=fixture(t)
 signed,err:=SignManifest(m,bytes.Repeat([]byte{0x42},32))
 if err!=nil {t.Fatal(err)}
 raw,err:=json.Marshal(signed)
 if err!=nil {t.Fatal(err)}
 if _,err:=DecodeSignedManifest(bytes.NewReader(raw));err!=nil {t.Fatal(err)}
 oversized:=append(append([]byte(nil),raw...),bytes.Repeat([]byte{' '},MaxSignedManifestJSONBytes+1-len(raw))...)
 if _,err:=DecodeSignedManifest(bytes.NewReader(oversized));err==nil {t.Fatal("oversized manifest accepted")}
}

func TestSignedManifestRejectsNestedUnknownFields(t *testing.T) {
 _,m:=fixture(t)
 signed,err:=SignManifest(m,bytes.Repeat([]byte{0x42},32))
 if err!=nil {t.Fatal(err)}
 raw,err:=json.Marshal(signed)
 if err!=nil {t.Fatal(err)}
 altered:=strings.Replace(string(raw),"\"files\":[","\"unknown\":true,\"files\":[",1)
 if _,err:=DecodeSignedManifest(strings.NewReader(altered));err==nil {t.Fatal("unknown nested field accepted")}
}
