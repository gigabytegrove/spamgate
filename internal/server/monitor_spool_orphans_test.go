package server

import (
 "testing"
 "time"
)

func TestUnpublishedSpoolAlertPersistsAndResolves(t *testing.T) {
 dir:=t.TempDir()
 m:=newOperationsMonitor(dir)
 now:=time.Date(2026,10,30,12,0,0,0,time.UTC)
 if err:=m.record(monitorSample{
  At:now,BootID:m.bootID,QueueEnabled:true,QueueAvailable:true,
  QueuePendingTemps:2,QueuePendingTempBytes:4096,
 });err!=nil{t.Fatal(err)}
 persisted:=newOperationsMonitor(dir)
 state,err:=persisted.snapshot();if err!=nil{t.Fatal(err)}
 if len(state.Alerts)!=1 || state.Alerts[0].Code!="queue_unpublished_spool" || state.Alerts[0].State!="open" {
  t.Fatalf("unpublished originals not surfaced: %+v",state.Alerts)
 }
 if len(state.Samples)!=1 || state.Samples[0].QueuePendingTemps!=2 || state.Samples[0].QueuePendingTempBytes!=4096 {
  t.Fatalf("missing persisted spool evidence: %+v",state.Samples)
 }
 if err:=persisted.record(monitorSample{At:now.Add(time.Minute),BootID:persisted.bootID,QueueEnabled:true,QueueAvailable:true});err!=nil{t.Fatal(err)}
 state,err=persisted.snapshot();if err!=nil{t.Fatal(err)}
 if len(state.Alerts)!=1 || state.Alerts[0].State!="resolved" || state.Alerts[0].ResolvedAt==nil {
  t.Fatalf("orphan alert not resolved after verified clean inventory: %+v",state.Alerts)
 }
}
