package spoolaudit

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)
const idA="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const idB="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
func fixture(id string) record {
 now:=time.Date(2026,10,30,12,0,0,0,time.UTC)
 r:=record{ID:id,Sender:"sensitive@example.invalid",Recipients:[]string{"secret@example.invalid"},
  Subject:"Confidential",Created:now,Updated:now,NextAttempt:now,State:"queued",Size:5,Raw:[]byte("hello")}
 r.IntegritySHA256=immutableDigest(r)
 r.StateSHA256=stateDigest(r)
 return r
}
func write(t *testing.T,dir,name string,r record){
 t.Helper()
 b,err:=json.Marshal(r)
 if err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(dir,name),b,0600);err!=nil{t.Fatal(err)}
}
func privateDir(t *testing.T)string{
 t.Helper()
 dir:=filepath.Join(t.TempDir(),"delivery-queue")
 if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
 return dir
}
func hasCode(r Report,code string)bool{
 for _,f:=range r.Findings{if f.Code==code{return true}}
 return false
}
func TestCleanPublishedAndPrivacy(t *testing.T){
 dir:=privateDir(t)
 write(t,dir,idA+".json",fixture(idA))
 r,err:=Audit(dir)
 if err!=nil||r.HasFindings()||r.Published!=1||r.States["queued"]!=1{t.Fatalf("audit: %+v %v",r,err)}
 b,_:=json.Marshal(r)
 if strings.Contains(string(b),"sensitive")||strings.Contains(string(b),"secret")||strings.Contains(string(b),"Confidential"){
  t.Fatal("report leaked private message data")
 }
}
func TestPendingWithoutFinalPreserved(t *testing.T){
 dir:=privateDir(t)
 write(t,dir,".pending-crash",fixture(idA))
 r,err:=Audit(dir)
 if err!=nil||r.PendingWithoutFinal!=1||!hasCode(r,"pending_without_final"){t.Fatalf("audit: %+v %v",r,err)}
 if _,err:=os.Stat(filepath.Join(dir,".pending-crash"));err!=nil{t.Fatal("audit modified pending file")}
}
func TestPendingWithFinalAndConflict(t *testing.T){
 dir:=privateDir(t)
 write(t,dir,idA+".json",fixture(idA))
 write(t,dir,".pending-old",fixture(idA))
 r,err:=Audit(dir)
 if err!=nil||r.PendingWithFinal!=1||!hasCode(r,"pending_with_final"){t.Fatalf("audit: %+v %v",r,err)}
 changed:=fixture(idA)
 changed.Sender="different@example.invalid"
 changed.IntegritySHA256=immutableDigest(changed)
 changed.StateSHA256=stateDigest(changed)
 write(t,dir,".pending-old",changed)
 r,err=Audit(dir)
 if err!=nil||!hasCode(r,"pending_conflict"){t.Fatalf("audit: %+v %v",r,err)}
}
func TestCorruptionAndLegacy(t *testing.T){
 dir:=privateDir(t)
 tampered:=fixture(idA)
 tampered.Raw=[]byte("other")
 write(t,dir,idA+".json",tampered)
 legacy:=fixture(idB)
 legacy.IntegritySHA256=""
 legacy.StateSHA256=""
 write(t,dir,idB+".json",legacy)
 r,err:=Audit(dir)
 if err!=nil||!hasCode(r,"unreadable_record")||!hasCode(r,"legacy_unsigned")||r.LegacyUnsigned!=1{
  t.Fatalf("audit: %+v %v",r,err)
 }
}
func TestUnsafePathsAndNames(t *testing.T){
 dir:=privateDir(t)
 outside:=filepath.Join(t.TempDir(),"outside")
 if err:=os.WriteFile(outside,[]byte("secret"),0600);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(outside,filepath.Join(dir,idA+".json"));err!=nil{t.Skip(err)}
 write(t,dir,"invalid.json",fixture(idB))
 r,err:=Audit(dir)
 if err!=nil||!hasCode(r,"unreadable_record")||!hasCode(r,"invalid_filename"){t.Fatalf("audit: %+v %v",r,err)}
 link:=filepath.Join(t.TempDir(),"link")
 if err:=os.Symlink(dir,link);err!=nil{t.Skip(err)}
 if _,err:=Audit(link);err==nil{t.Fatal("followed symlinked spool directory")}
}
func TestOversizeAndInvalidState(t *testing.T){
 dir:=privateDir(t)
 f,err:=os.Create(filepath.Join(dir,idA+".json"));if err!=nil{t.Fatal(err)}
 if err:=f.Truncate(maxRecordBytes+1);err!=nil{t.Fatal(err)}
 if err:=f.Close();err!=nil{t.Fatal(err)}
 bad:=fixture(idB);bad.State="invented";write(t,dir,idB+".json",bad)
 r,err:=Audit(dir)
 if err!=nil||r.Published!=2||len(r.Findings)!=2{t.Fatalf("audit: %+v %v",r,err)}
}
func TestDigestMatchesExactEnvelopeAndState(t *testing.T){
 r:=fixture(idA)
 if immutableDigest(r)!=r.IntegritySHA256||stateDigest(r)!=r.StateSHA256{t.Fatal("fixture digests disagree")}
 r.Attempts++
 if stateDigest(r)==r.StateSHA256||immutableDigest(r)!=r.IntegritySHA256{t.Fatal("mutable field changed immutable digest")}
 r=fixture(idA)
 r.Recipients[0]="elsewhere@example.invalid"
 if immutableDigest(r)==r.IntegritySHA256{t.Fatal("recipient tampering not detected")}
}
