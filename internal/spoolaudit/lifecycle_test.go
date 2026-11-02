package spoolaudit

import (
 "encoding/json"
 "testing"
 "time"
)

func TestLifecycleAnomalies(t *testing.T){
 now:=time.Date(2026,11,1,22,0,0,0,time.UTC)
 base:=record{ID:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",Sender:"s@example.invalid",Recipients:[]string{"r@example.invalid"},Created:now,Updated:now,NextAttempt:now,Attempts:1,State:"queued"}
 tests:=[]struct{name string;change func(*record);code string}{
  {"normal queued",func(*record){},""},
  {"normal delivered",func(r *record){r.State="delivered";r.DeliveredAt=now},""},
  {"normal dead",func(r *record){r.State="dead"},""},
  {"normal discard pending",func(r *record){r.State="discard_pending";r.Attempts=0},""},
  {"missing created",func(r *record){r.Created=time.Time{}},"missing_lifecycle_time"},
  {"missing updated",func(r *record){r.Updated=time.Time{}},"missing_lifecycle_time"},
  {"missing next attempt",func(r *record){r.NextAttempt=time.Time{}},"missing_lifecycle_time"},
  {"too many attempts",func(r *record){r.Attempts=17},"attempt_limit_exceeded"},
  {"delivered without receipt",func(r *record){r.State="delivered"},"unproven_delivery_state"},
  {"delivered without attempt",func(r *record){r.State="delivered";r.Attempts=0;r.DeliveredAt=now},"unproven_delivery_state"},
  {"dead without attempt",func(r *record){r.State="dead";r.Attempts=0},"unproven_delivery_attempt"},
  {"delivering without attempt",func(r *record){r.State="delivering";r.Attempts=0},"unproven_delivery_attempt"},
  {"queued with receipt",func(r *record){r.DeliveredAt=now},"unexpected_delivery_receipt"},
  {"discard with receipt",func(r *record){r.State="discard_pending";r.DeliveredAt=now},"unexpected_delivery_receipt"},
  {"dead with receipt",func(r *record){r.State="dead";r.DeliveredAt=now},"unexpected_delivery_receipt"},
  {"matching scan",func(r *record){r.Scan=[]byte(`{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sender":"s@example.invalid","recipients":["r@example.invalid"]}`)},""},
  {"foreign scan id",func(r *record){r.Scan=[]byte(`{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sender":"s@example.invalid","recipients":["r@example.invalid"]}`)},"scan_envelope_mismatch"},
  {"foreign scan sender",func(r *record){r.Scan=[]byte(`{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sender":"other@example.invalid","recipients":["r@example.invalid"]}`)},"scan_envelope_mismatch"},
  {"foreign scan recipients",func(r *record){r.Scan=[]byte(`{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sender":"s@example.invalid","recipients":["other@example.invalid"]}`)},"scan_envelope_mismatch"},
  {"legacy scan absent",func(r *record){r.Scan=nil},""},
  {"legacy scan null",func(r *record){r.Scan=json.RawMessage("null")},""},
 }
 for _,tc:=range tests {
  t.Run(tc.name,func(t *testing.T){
   r:=base;tc.change(&r)
   findings:=lifecycleAnomalies(r)
   if tc.code==""&&len(findings)!=0{t.Fatalf("unexpected findings: %+v",findings)}
   if tc.code!=""{
    found:=false
    for _,f:=range findings{if f.code==tc.code{found=true}}
    if !found{t.Fatalf("missing %s: %+v",tc.code,findings)}
   }
  })
 }
}
