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
 "github.com/gigabytegrove/spamgate/internal/spooljson"
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
 PendingDuplicateIDs int `json:"pending_duplicate_ids"`
 PendingConflictingIDs int `json:"pending_conflicting_ids"`
 LifecycleAnomalies int `json:"lifecycle_anomalies"`
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
 if err:=validateAuditRecordMetadata(path,info);err!=nil{return record{},fmt.Errorf("unsafe spool metadata: %w",err)}
 f,err:=os.Open(path)
 if err!=nil{return record{},err}
 defer f.Close()
 opened,err:=f.Stat()
 if err!=nil{return record{},err}
 if !opened.Mode().IsRegular()||!os.SameFile(info,opened)||opened.Size()!=info.Size(){
  return record{},errors.New("spool path changed during open")
 }
 if err:=validateAuditRecordMetadata(path,opened);err!=nil{return record{},fmt.Errorf("unsafe opened spool metadata: %w",err)}
 data,err:=io.ReadAll(io.LimitReader(f,maxRecordBytes+1))
 if err!=nil{return record{},err}
 after,err:=f.Stat()
 if err!=nil{return record{},err}
 if int64(len(data))!=info.Size()||after.Size()!=info.Size()||!after.ModTime().Equal(info.ModTime())||!os.SameFile(opened,after)||!sameAuditChangeTime(info,after){
  return record{},errors.New("spool record changed during read")
 }
 if err:=validateAuditRecordMetadata(path,after);err!=nil{return record{},fmt.Errorf("unsafe spool metadata after read: %w",err)}
 if err:=verifyRecordPathStable(path,opened);err!=nil{return record{},err}
 var rec record
 if err:=spooljson.Validate(data);err!=nil{return record{},fmt.Errorf("invalid or ambiguous spool JSON: %w",err)}
 if err:=json.Unmarshal(data,&rec);err!=nil{return record{},errors.New("invalid spool JSON")}
 if !validID(rec.ID)||rec.Size<1||rec.Size>10<<20||len(rec.Raw)!=rec.Size||
  len(rec.Recipients)==0||len(rec.Recipients)>1000||rec.Attempts<0 {
  return record{},errors.New("invalid envelope, original length or queue ID")
 }
 switch rec.State {
 case "queued","delivering","dead","delivered","discard_pending":
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
 // A valid pending record can exist without a published counterpart after
 // an interrupted fsync/rename. Multiple such records with the same ID
 // must be reported before any operator considers manual recovery.
 pendingByID:=make(map[string]map[string]struct{})
 // Count each verified pending-to-final identity only once, even when
 // interrupted writes left multiple identical pending files behind.
 reconciledIDs:=make(map[string]struct{})
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
    // An incomplete scan is never a successful queue-integrity audit.
    // Validate the directory pathname even on the entry-limit exit.
    if err:=verifyAuditDirectoryPath(dir,opened);err!=nil {
     return out,fmt.Errorf("spool directory changed during truncated audit: %w",err)
    }
    return out,errors.New("spool audit entry limit exceeded; results incomplete")
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
   // Signed records with impossible lifecycles are not trusted states.
   anomalies:=lifecycleAnomalies(rec)
   if published&&rec.ID==strings.TrimSuffix(name,".json")&&
    rec.IntegritySHA256!=""&&rec.StateSHA256!=""&&len(anomalies)==0 {out.States[rec.State]++}
   if rec.IntegritySHA256==""||rec.StateSHA256==""{
    out.LegacyUnsigned++
    out.add("legacy_unsigned",name,"one or both integrity digests are absent; provenance cannot be verified")
   }
   for _,anomaly:=range anomalies{
    out.LifecycleAnomalies++
    out.add(anomaly.code,name,anomaly.detail)
   }
   if !pending{continue}
   digest:=immutableDigest(rec)
   seen,exists:=pendingByID[rec.ID]
   if !exists {
    seen=make(map[string]struct{})
    pendingByID[rec.ID]=seen
   } else {
    out.PendingDuplicateIDs++
    if _,duplicate:=seen[digest];duplicate {
     out.add("pending_duplicate",name,"multiple unpublished records share one immutable original; never automatically replay")
    } else {
     out.PendingConflictingIDs++
     out.add("pending_id_collision",name,"multiple unpublished records share one queue ID with different immutable originals; never automatically replay")
    }
   }
   seen[digest]=struct{}{}
   final,finalErr:=readRecord(filepath.Join(dir,rec.ID+".json"))
   if errors.Is(finalErr,os.ErrNotExist){
    out.PendingWithoutFinal++
    out.add("pending_without_final",name,"valid unpublished original; SMTP acknowledgement and delivery state unknown")
   }else if finalErr!=nil{
    out.add("pending_final_unreadable",name,"published counterpart cannot be verified")
   }else{
    // The published filename is derived from the pending ID, but the
    // published JSON can carry a different, individually valid queue ID.
    // Never treat that unrelated original as the pending record's final.
    if final.ID!=rec.ID {
     out.add("pending_final_id_mismatch",name,"published filename matches pending ID but its signed envelope belongs to another queue ID; do not replay")
     continue
    }
    // A matching queue ID alone cannot prove that the published final
    // belongs to this pending original. Count only a digest match.
    if immutableDigest(rec)!=immutableDigest(final){
     out.add("pending_conflict",name,"published counterpart has a different immutable envelope/original; not reconciled")
     continue
    }
    // Legacy records without both integrity digests cannot establish a
    // verified reconciliation. Matching bytes alone are not provenance.
    if rec.IntegritySHA256==""||rec.StateSHA256==""||
     final.IntegritySHA256==""||final.StateSHA256=="" {
     out.add("pending_final_unsigned",name,"matching unpublished and published originals lack complete integrity evidence; reconciliation unverified; do not replay")
     continue
    }
    if len(anomalies)>0||len(lifecycleAnomalies(final))>0 {
     out.add("pending_final_lifecycle_invalid",name,"matching records have lifecycle anomalies; reconciliation unverified; do not replay")
     continue
    }
    if _,already:=reconciledIDs[rec.ID];already {
     out.add("pending_final_duplicate",name,"another unpublished record already reconciled to this published queue ID; do not replay")
     continue
    }
    reconciledIDs[rec.ID]=struct{}{}
    out.PendingWithFinal++
    out.add("pending_with_final",name,"signed unpublished original exists alongside matching signed published record; do not replay")
   }
  }
  if errors.Is(err,io.EOF){break}
 }
 // An opened directory descriptor remains readable after rename/unlink.
 // Refuse to present that detached tree as the current spool pathname.
 if err:=verifyAuditDirectoryPath(dir,opened);err!=nil{return out,fmt.Errorf("spool directory changed during audit: %w",err)}
 // The bounded findings array is diagnostic evidence, not a complete audit
 // once the limit is reached. Do not certify an unreported tail as clean.
 if out.Truncated {
  return out,errors.New("spool audit finding limit exceeded; results incomplete")
 }
 return out,nil
}
func (r Report) HasFindings() bool {return len(r.Findings)!=0||r.Truncated}
func (r Report) Explain() string {
 return fmt.Sprintf("examined=%d published=%d pending=%d pending_without_final=%d pending_with_final=%d pending_duplicate_ids=%d pending_conflicting_ids=%d lifecycle_anomalies=%d legacy_unsigned=%d findings=%d truncated=%t",
  r.Examined,r.Published,r.Pending,r.PendingWithoutFinal,r.PendingWithFinal,r.PendingDuplicateIDs,r.PendingConflictingIDs,r.LifecycleAnomalies,r.LegacyUnsigned,len(r.Findings),r.Truncated)
}
