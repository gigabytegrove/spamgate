package spoolaudit

import (
 "encoding/json"
 "slices"
)

// lifecycleAnomaly describes an impossible or suspicious transition in a
// persisted delivery record. These are forensic findings, not repair orders.
// In particular, clock comparisons are deliberately limited: wall clocks can
// move backwards on a real mail host without corrupting a queue record.
type lifecycleAnomaly struct {
 code string
 detail string
}

func lifecycleAnomalies(rec record) []lifecycleAnomaly {
 var findings []lifecycleAnomaly
 add:=func(code,detail string){findings=append(findings,lifecycleAnomaly{code,detail})}
 if rec.Created.IsZero()||rec.Updated.IsZero()||rec.NextAttempt.IsZero(){
  add("missing_lifecycle_time","one or more required queue timestamps are absent")
 }
 if rec.Attempts>16 {
  add("attempt_limit_exceeded","record exceeds the native delivery attempt ceiling")
 }
 switch rec.State {
 case "delivered":
  if rec.Attempts==0||rec.DeliveredAt.IsZero(){
   add("unproven_delivery_state","delivered state lacks a completed relay attempt or receipt time; manual verification required")
  }
 case "delivering","dead":
  if rec.Attempts==0{
   add("unproven_delivery_attempt","in-flight or dead-letter state has no recorded relay attempt")
  }
  if !rec.DeliveredAt.IsZero(){
   add("unexpected_delivery_receipt","non-delivered state contains a completed relay receipt time")
  }
 case "queued","discard_pending":
  if !rec.DeliveredAt.IsZero(){
   add("unexpected_delivery_receipt","non-delivered state contains a completed relay receipt time")
  }
 }
 // A scan is optional for pre-upgrade spool files. When present it must
 // describe the immutable envelope in this record, not another message.
 if len(rec.Scan)>0&&string(rec.Scan)!="null"{
  var scan struct {
   ID string `json:"id"`
   Sender string `json:"sender"`
   Recipients []string `json:"recipients"`
  }
  if err:=json.Unmarshal(rec.Scan,&scan);err!=nil||
   scan.ID!=rec.ID||scan.Sender!=rec.Sender||!slices.Equal(scan.Recipients,rec.Recipients){
   add("scan_envelope_mismatch","persisted scan evidence does not match the immutable queue envelope")
  }
 }
 return findings
}
