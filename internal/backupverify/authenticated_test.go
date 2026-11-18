package backupverify

import (
 "bytes"
 "encoding/json"
 "strings"
 "testing"
)

func TestAuthenticatedBackupRoundTrip(t *testing.T) {
 root,m:=fixture(t)
 key:=bytes.Repeat([]byte{0x5a},32)
 signed,err:=SignManifest(m,key)
 if err!=nil { t.Fatal(err) }
 if err:=AuthenticateManifest(signed,key);err!=nil { t.Fatal(err) }
 report,err:=VerifyAuthenticated(root,signed,key)
 if err!=nil || report.Files!=1 || report.Bytes!=7 { t.Fatalf("report=%+v err=%v",report,err) }
 encoded,err:=json.Marshal(signed)
 if err!=nil { t.Fatal(err) }
 decoded,err:=DecodeSignedManifest(bytes.NewReader(encoded))
 if err!=nil { t.Fatal(err) }
 if _,err:=VerifyAuthenticated(root,decoded,key);err!=nil { t.Fatal(err) }
}

func TestAuthenticatedBackupRejectsTampering(t *testing.T) {
 root,m:=fixture(t)
 key:=bytes.Repeat([]byte{0x31},32)
 signed,err:=SignManifest(m,key)
 if err!=nil { t.Fatal(err) }
 tests:=[]struct{name string; change func(*SignedManifest)}{
  {"size",func(s *SignedManifest){s.Manifest.Files[0].Size++}},
  {"path",func(s *SignedManifest){s.Manifest.Files[0].Path="db/other.db"}},
  {"digest",func(s *SignedManifest){s.Manifest.Files[0].SHA256=strings.Repeat("0",64)}},
  {"mac",func(s *SignedManifest){s.MAC=strings.Repeat("0",64)}},
  {"uppercase mac",func(s *SignedManifest){s.MAC=strings.ToUpper(s.MAC)}},
 }
 for _,tc:=range tests {t.Run(tc.name,func(t *testing.T){
  copy:=signed
  copy.Manifest.Files=append([]Entry(nil),signed.Manifest.Files...)
  tc.change(&copy)
  if _,err:=VerifyAuthenticated(root,copy,key);err==nil {t.Fatal("tampering accepted")}
 })}
 if _,err:=VerifyAuthenticated(root,signed,bytes.Repeat([]byte{0x32},32));err==nil {t.Fatal("wrong key accepted")}
 if _,err:=SignManifest(m,[]byte("short"));err==nil {t.Fatal("short key accepted")}
}

func TestSignedManifestJSONStrictness(t *testing.T) {
 _,m:=fixture(t)
 signed,err:=SignManifest(m,bytes.Repeat([]byte{0x44},32))
 if err!=nil {t.Fatal(err)}
 data,err:=json.Marshal(signed)
 if err!=nil {t.Fatal(err)}
 for _,input:=range []string{
  string(data)+" {}",
  strings.Replace(string(data),"\"manifest\":","\"unexpected\":true,\"manifest\":",1),
  strings.Replace(string(data),"\"version\":1","\"version\":2",1),
 } {
  if _,err:=DecodeSignedManifest(strings.NewReader(input));err==nil {t.Fatalf("accepted %s",input)}
 }
}
