package spooltrend

import (
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// Each independent forensic counter must block a supposedly successful
// audit, including callers that bypass Load and construct Snapshot directly.
func TestAuditCountersCannotMasqueradeAsCleanEvidence(t *testing.T) {
 cases:=[]struct{name string; set func(*Snapshot)}{
  {"pending_without_final",func(s *Snapshot){s.PendingWithoutFinal=1}},
  {"pending_with_final",func(s *Snapshot){s.PendingWithFinal=1}},
  {"pending_duplicate_ids",func(s *Snapshot){s.PendingDuplicateIDs=1}},
  {"pending_conflicting_ids",func(s *Snapshot){s.PendingConflictingIDs=1}},
  {"lifecycle_anomalies",func(s *Snapshot){s.LifecycleAnomalies=1}},
  {"legacy_unsigned",func(s *Snapshot){s.LegacyUnsigned=1}},
  {"unreadable_records",func(s *Snapshot){s.UnreadableRecords=1}},
  {"invalid_filenames",func(s *Snapshot){s.InvalidFilenames=1}},
  {"unexpected_entries",func(s *Snapshot){s.UnexpectedEntries=1}},
  {"dropped_findings",func(s *Snapshot){s.DroppedFindings=1}},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   before:=snapshot(map[string]int{"queued":1})
   after:=snapshot(map[string]int{"queued":1})
   tc.set(&after)
   if _,err:=Compare(before,after,-1,-1);err==nil||!strings.Contains(err.Error(),tc.name){
    t.Fatalf("direct comparison accepted %s: %v",tc.name,err)
   }
   body:=map[string]any{
    "gate_passed":true,"gate_failures":[]string{},"examined":1,
    "published":1,"pending":0,"states":map[string]int{"queued":1},
    "findings":[]json.RawMessage{},"truncated":false,
    tc.name:1,
   }
   raw,err:=json.Marshal(body);if err!=nil{t.Fatal(err)}
   path:=filepath.Join(t.TempDir(),"audit.json")
   if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
   if _,err:=Load(path);err==nil||!strings.Contains(err.Error(),tc.name){
    t.Fatalf("file load accepted %s: %v",tc.name,err)
   }
  })
 }
}

func TestCleanAuditCountersRemainCompatible(t *testing.T) {
 s:=snapshot(map[string]int{"queued":2})
 if err:=validateAuditCounters(s);err!=nil{t.Fatal(err)}
}
