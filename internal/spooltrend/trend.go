// Package spooltrend compares privacy-limited, verified spool-audit snapshots.
// Snapshot comparison is not proof of mail delivery or a coherent live queue.
package spooltrend

import (
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "sort"
 "strings"
)

const maxReportSize = 4 << 20

type Snapshot struct {
 GatePassed *bool `json:"gate_passed"`
 GateFailures []string `json:"gate_failures"`
 Examined int `json:"examined"`
 Published int `json:"published"`
 Pending int `json:"pending"`
 States map[string]int `json:"states"`
 Findings []json.RawMessage `json:"findings"`
 Truncated bool `json:"truncated"`
}
type Result struct {
 GatePassed bool `json:"gate_passed"`
 GateFailures []string `json:"gate_failures"`
 QueueDelta int `json:"queue_delta"`
 DeliveringDelta int `json:"delivering_delta"`
 DeadDelta int `json:"dead_delta"`
 PendingDelta int `json:"pending_delta"`
 Before map[string]int `json:"before"`
 After map[string]int `json:"after"`
}
func Load(path string)(Snapshot,error){
 fi,err:=os.Lstat(path)
 if err!=nil{return Snapshot{},err}
 if !fi.Mode().IsRegular() || fi.Size()<=0 || fi.Size()>maxReportSize {return Snapshot{},errors.New("report must be a bounded regular file")}
 f,err:=openEvidence(path)
 if err!=nil{return Snapshot{},err}
 defer f.Close()
 opened,err:=f.Stat()
 if err!=nil{return Snapshot{},err}
 if !opened.Mode().IsRegular() || !os.SameFile(fi,opened) {return Snapshot{},errors.New("report changed during open")}
 data,err:=io.ReadAll(io.LimitReader(f,maxReportSize+1))
 if err!=nil{return Snapshot{},err}
 if len(data)>maxReportSize{return Snapshot{},errors.New("report exceeds size limit")}
 if err:=validateJSON(data);err!=nil{return Snapshot{},err}
 dec:=json.NewDecoder(strings.NewReader(string(data)))
 var s Snapshot
 // Spool reports contain additional fields; parse into a raw object first
 // to retain forward compatibility while enforcing required safety fields.
 var raw map[string]json.RawMessage
 if err:=dec.Decode(&raw);err!=nil{return Snapshot{},err}
 var extra any
 if err:=dec.Decode(&extra);err!=io.EOF{return Snapshot{},errors.New("trailing JSON or oversized input")}
 for _,key:=range []string{"gate_passed","examined","published","pending","states","findings","truncated"} {
  if _,ok:=raw[key];!ok{return Snapshot{},fmt.Errorf("missing %s",key)}
 }
 data,err:=json.Marshal(raw)
 if err!=nil{return Snapshot{},err}
 if err:=json.Unmarshal(data,&s);err!=nil{return Snapshot{},err}
 after,err:=f.Stat()
 if err!=nil{return Snapshot{},err}
 if !os.SameFile(opened,after)||after.Size()!=fi.Size()||!after.ModTime().Equal(fi.ModTime()) {return Snapshot{},errors.New("report changed during read")}
 if err:=validateSnapshot(s);err!=nil{return Snapshot{},err}
 if s.Examined<0||s.Published<0||s.Pending<0||s.Published>s.Examined || s.Pending>s.Examined-s.Published||s.States==nil {
  return Snapshot{},errors.New("invalid spool counts")
 }
 total:=0
 for state,n:=range s.States {
  switch state {case "queued","delivering","dead","delivered","discard_pending":default:return Snapshot{},fmt.Errorf("invalid state %q",state)}
  if n<0{return Snapshot{},errors.New("negative state count")}
  if n>s.Published-total{return Snapshot{},errors.New("verified states exceed published records")}
  total+=n
 }
 if total!=s.Published {return Snapshot{},errors.New("verified state count does not match published records")}
 return s,nil
}
func Compare(before,after Snapshot,maxQueuedGrowth,maxDeadGrowth int)(Result,error){
 if maxQueuedGrowth < -1 || maxDeadGrowth < -1{return Result{},errors.New("invalid limits")}
 // Callers constructing snapshots directly must meet the same acceptance contract.
 for _,s:=range []Snapshot{before,after} {
  if err:=validateSnapshot(s);err!=nil{return Result{},err}
 }
 a,b:=before.States,after.States
 r:=Result{GatePassed:true,Before:map[string]int{},After:map[string]int{},QueueDelta:b["queued"]-a["queued"],DeliveringDelta:b["delivering"]-a["delivering"],DeadDelta:b["dead"]-a["dead"],PendingDelta:after.Pending-before.Pending}
 for _,state:=range []string{"queued","delivering","dead","delivered","discard_pending"} {r.Before[state]=a[state];r.After[state]=b[state]}
 if maxQueuedGrowth>=0&&r.QueueDelta>maxQueuedGrowth {r.GateFailures=append(r.GateFailures,fmt.Sprintf("queued_growth=%d exceeds max-queue-growth=%d",r.QueueDelta,maxQueuedGrowth))}
 if maxDeadGrowth>=0&&r.DeadDelta>maxDeadGrowth {r.GateFailures=append(r.GateFailures,fmt.Sprintf("dead_growth=%d exceeds max-dead-growth=%d",r.DeadDelta,maxDeadGrowth))}
 sort.Strings(r.GateFailures)
 r.GatePassed=len(r.GateFailures)==0
 return r,nil
}
// validateSnapshot also protects callers that construct Snapshot values directly.
func validateSnapshot(s Snapshot) error {
 if s.GatePassed==nil || !*s.GatePassed || s.Truncated || len(s.Findings)!=0 || len(s.GateFailures)!=0 {return errors.New("unqualified input snapshot")}
 if s.Examined<0 || s.Published<0 || s.Pending<0 || s.Published>s.Examined || s.Pending>s.Examined-s.Published || s.States==nil {return errors.New("invalid snapshot counts")}
 total:=0
 for state,n:=range s.States {
  switch state {case "queued","delivering","dead","delivered","discard_pending":default:return fmt.Errorf("invalid state %q",state)}
  if n<0 || n>s.Published-total {return errors.New("invalid verified state count")}
  total+=n
 }
 if total!=s.Published {return errors.New("published records missing verified states")}
 return nil
}
