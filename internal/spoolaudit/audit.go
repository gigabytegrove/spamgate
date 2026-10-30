// Package spoolaudit performs read-only forensic checks on SpamGate's native
// SMTP delivery queue. It never promotes, retries, deletes or rewrites mail.
package spoolaudit

import (
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "time"
)

const (
 maxRecordBytes int64 = 20 << 20
 maxEntries = 4096
 maxFindings = 512
)
type Finding struct {
 Code string `json:"code"`
 Object string `json:"object"`
 Detail string `json:"detail"`
}
type Report struct {
 Examined int `json:"examined"`
 Published int `json:"published"`
 Pending int `json:"pending"`
 PendingWithoutFinal int `json:"pending_without_final"`
 PendingWithFinal int `json:"pending_with_final"`
 LegacyUnsigned int `json:"legacy_unsigned"`
 States map[string]int `json:"states"`
 Findings []Finding `json:"findings"`
 Truncated bool `json:"truncated"`
}
// record mirrors the JSON serialization of transport.spoolRecord.
// Do not reorder fields in immutableDigest/stateDigest without updating
// transport.spoolDigest/spoolStateDigest and their compatibility test.
type record struct {
 ID string `json:"id"`
 Sender string `json:"sender"`
 Recipients []string `json:"recipients"`
 Subject string `json:"subject"`
 Created time.Time `json:"created"`
 NextAttempt time.Time `json:"next_attempt"`
 Updated time.Time `json:"updated"`
 Attempts int `json:"attempts"`
 State string `json:"state"`
 LastError string `json:"last_error,omitempty"`
 Size int `json:"size"`
 DeliveredAt time.Time `json:"delivered_at,omitempty"`
 Raw []byte `json:"raw"`
 IntegritySHA256 string `json:"integrity_sha256,omitempty"`
 StateSHA256 string `json:"state_sha256,omitempty"`
 Scan json.RawMessage `json:"scan,omitempty"`
}
func immutableDigest(r record) string {
 payload, _ := json.Marshal(struct {
  ID string `json:"id"`
  Sender string `json:"sender"`
  Recipients []string `json:"recipients"`
  Raw []byte `json:"raw"`
  Scan json.RawMessage `json:"scan,omitempty"`
 }{r.ID,r.Sender,r.Recipients,r.Raw,r.Scan})
 sum:=sha256.Sum256(payload)
 return hex.EncodeToString(sum[:])
}
func stateDigest(r record) string {
 payload, _ := json.Marshal(struct {
  ID string `json:"id"`
  Immutable string `json:"immutable"`
  Subject string `json:"subject"`
  Created time.Time `json:"created"`
  Updated time.Time `json:"updated"`
  NextAttempt time.Time `json:"next_attempt"`
  Attempts int `json:"attempts"`
  State string `json:"state"`
  LastError string `json:"last_error"`
  DeliveredAt time.Time `json:"delivered_at"`
  Size int `json:"size"`
 }{r.ID,r.IntegritySHA256,r.Subject,r.Created,r.Updated,r.NextAttempt,r.Attempts,r.State,r.LastError,r.DeliveredAt,r.Size})
 sum:=sha256.Sum256(payload)
 return hex.EncodeToString(sum[:])
}
func validID(id string) bool {
 if len(id)!=32{return false}
 for _,c:=range id {
  if (c<'0'||c>'9')&&(c<'a'||c>'f'){return false}
 }
 return true
}
func (r *Report) add(code,name,detail string) {
 if len(r.Findings)>=maxFindings {r.Truncated=true;return}
 r.Findings=append(r.Findings,Finding{code,strconv.QuoteToASCII(name),detail})
}
func readRecord(path string) (record,error) {
 info,err:=os.Lstat(path)
 if err!=nil{return record{},err}
 if !info.Mode().IsRegular()||info.Size()<2||info.Size()>maxRecordBytes {
  return record{},errors.New("not a bounded regular spool record")
 }
 f,err:=os.Open(path)
 if err!=nil{return record{},err}
 defer f.Close()
 opened,err:=f.Stat()
 if err!=nil{return record{},err}
 if !opened.Mode().IsRegular()||!os.SameFile(info,opened)||opened.Size()!=info.Size(){
  return record{},errors.New("spool path changed during open")
 }
 data,err:=io.ReadAll(io.LimitReader(f,maxRecordBytes+1))
 if err!=nil{return record{},err}
 after,err:=f.Stat()
 if err!=nil{return record{},err}
 if int64(len(data))!=info.Size()||after.Size()!=info.Size()||!after.ModTime().Equal(info.ModTime()){
  return record{},errors.New("spool record changed during read")
 }
 var rec record
 if err:=json.Unmarshal(data,&rec);err!=nil{return record{},errors.New("invalid spool JSON")}
 if !validID(rec.ID)||rec.Size<1||rec.Size>10<<20||len(rec.Raw)!=rec.Size||
  len(rec.Recipients)==0||len(rec.Recipients)>1000||rec.Attempts<0 {
  return record{},errors.New("invalid envelope, original length or queue ID")
 }
 switch rec.State {
 case "queued","delivering","dead","delivered":
 default:return record{},errors.New("invalid delivery state")
 }
 if rec.IntegritySHA256!=""&&rec.IntegritySHA256!=immutableDigest(rec){
  return record{},errors.New("immutable envelope/original digest mismatch")
 }
 if rec.StateSHA256!=""&&rec.StateSHA256!=stateDigest(rec){
  return record{},errors.New("mutable state digest mismatch")
 }
 return rec,nil
}
// Audit examines a bounded directory without modifying anything.
// Live scans are observations, not transactionally coherent snapshots.
// Pending files are NEVER replayed automatically.
func Audit(dir string) (Report,error) {
 out:=Report{States:make(map[string]int),Findings:make([]Finding,0)}
 info,err:=os.Lstat(dir)
 if err!=nil{return out,err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0022!=0{
  return out,errors.New("spool directory must be real and not group/world writable")
 }
 d,err:=os.Open(dir)
 if err!=nil{return out,err}
 defer d.Close()
 opened,err:=d.Stat()
 if err!=nil{return out,err}
 if !opened.IsDir()||!os.SameFile(info,opened){
  return out,errors.New("spool directory changed during open")
 }
 for {
  entries,err:=d.ReadDir(128)
  if err!=nil&&!errors.Is(err,io.EOF){return out,err}
  for _,entry:=range entries {
   out.Examined++
   if out.Examined>maxEntries {
    out.add("entry_limit","delivery-queue","more than 4096 directory entries; audit incomplete")
    out.Truncated=true
    return out,nil
   }
   name:=entry.Name()
   pending:=strings.HasPrefix(name,".pending-")
   published:=strings.HasSuffix(name,".json")&&!pending
   if !pending&&!published{continue}
   if pending{out.Pending++}else{out.Published++}
   if published&&!validID(strings.TrimSuffix(name,".json")){
    out.add("invalid_filename",name,"published spool filename is not a lowercase 32-character queue ID")
    continue
   }
   rec,readErr:=readRecord(filepath.Join(dir,name))
   if readErr!=nil {out.add("unreadable_record",name,readErr.Error());continue}
   if published&&rec.ID!=strings.TrimSuffix(name,".json"){
    out.add("id_mismatch",name,"record ID does not match its published filename")
   }
   if published{out.States[rec.State]++}
   if rec.IntegritySHA256==""||rec.StateSHA256==""{
    out.LegacyUnsigned++
    out.add("legacy_unsigned",name,"one or both integrity digests are absent; provenance cannot be verified")
   }
   if !pending{continue}
   final,finalErr:=readRecord(filepath.Join(dir,rec.ID+".json"))
   if errors.Is(finalErr,os.ErrNotExist){
    out.PendingWithoutFinal++
    out.add("pending_without_final",name,"valid unpublished original; SMTP acknowledgement and delivery state unknown")
   }else if finalErr!=nil{
    out.add("pending_final_unreadable",name,"published counterpart cannot be verified")
   }else{
    out.PendingWithFinal++
    if immutableDigest(rec)!=immutableDigest(final){
     out.add("pending_conflict",name,"published counterpart has a different immutable envelope/original")
    }else{
     out.add("pending_with_final",name,"unpublished state copy exists alongside a published record; do not replay")
    }
   }
  }
  if errors.Is(err,io.EOF){break}
 }
 return out,nil
}
func (r Report) HasFindings() bool {return len(r.Findings)!=0||r.Truncated}
func (r Report) Explain() string {
 return fmt.Sprintf("examined=%d published=%d pending=%d pending_without_final=%d pending_with_final=%d legacy_unsigned=%d findings=%d truncated=%t",
  r.Examined,r.Published,r.Pending,r.PendingWithoutFinal,r.PendingWithFinal,r.LegacyUnsigned,len(r.Findings),r.Truncated)
}
