package transport

import (
 "context"
 "encoding/json"
 "os"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

// A pre-digest legacy spool record must never be able to redirect a queued
// original through a null recipient, even though encoding/json maps null
// elements in []string to empty strings. Reject before queue replay.
func TestLegacyNullRecipientNeverRelayed(t *testing.T) {
 sends := 0
 q, store, dir := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
  sends++
  return nil
 })
 msg := core.Message{
  ID: core.ID(), Sender: "sender@example.invalid",
  Recipients: []string{"recipient@example.invalid"}, Action: "accept",
 }
 if err := q.Enqueue(msg, []byte("Subject: original\r\n\r\nbody")); err != nil {t.Fatal(err)}
 path := q.path(msg.ID)
 raw, err := os.ReadFile(path)
 if err != nil {t.Fatal(err)}
 var record map[string]json.RawMessage
 if err := json.Unmarshal(raw, &record); err != nil {t.Fatal(err)}
 record["recipients"] = json.RawMessage(`[null]`)
 delete(record, "integrity_sha256")
 delete(record, "state_sha256")
 corrupted, err := json.Marshal(record)
 if err != nil {t.Fatal(err)}
 if err := os.WriteFile(path, corrupted, 0600); err != nil {t.Fatal(err)}
 if _, err := q.Snapshot(); err == nil {t.Fatal("null recipient entered queue inventory")}
 if err := q.ProcessDue(context.Background()); err == nil || sends != 0 {
  t.Fatalf("unsafe original relayed: err=%v sends=%d",err,sends)
 }
 if _, err := os.Stat(path); err != nil {t.Fatalf("original lost: %v",err)}
 if _, err := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error{return nil}); err == nil {
  t.Fatal("restart accepted null recipient")
 }
}

 // This regression covers legacy records without integrity digests. A
 // malformed escaped envelope must never enter inventory or relay on restart.
func TestLegacyControlEnvelopeNeverRelayed(t *testing.T) {
 cases := []struct{
  name string
  field string
  value any
 }{
  {"sender newline", "sender", "sender@example.invalid\r\nMAIL FROM:<spoof@example.invalid>"},
  {"recipient newline", "recipients", []string{"user@example.invalid\nRCPT TO:<spoof@example.invalid>"}},
  {"recipient tab", "recipients", []string{"user\t@example.invalid"}},
  {"recipient DEL", "recipients", []string{"user\x7f@example.invalid"}},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   sends:=0
   q,store,dir:=newRecoveryQueue(t,func(context.Context,core.Message,[]byte)error{sends++;return nil})
   msg:=core.Message{ID:core.ID(),Sender:"sender@example.invalid",Recipients:[]string{"user@example.invalid"},Action:"accept"}
   if err:=q.Enqueue(msg,[]byte("Subject: test\r\n\r\noriginal"));err!=nil {t.Fatal(err)}
   path:=q.path(msg.ID)
   original,err:=os.ReadFile(path);if err!=nil {t.Fatal(err)}
   var record map[string]json.RawMessage
   if err:=json.Unmarshal(original,&record);err!=nil {t.Fatal(err)}
   encoded,err:=json.Marshal(tc.value);if err!=nil {t.Fatal(err)}
   record[tc.field]=encoded
   delete(record,"integrity_sha256")
   delete(record,"state_sha256")
   corrupted,err:=json.Marshal(record);if err!=nil {t.Fatal(err)}
   if err:=os.WriteFile(path,corrupted,0600);err!=nil {t.Fatal(err)}
   if _,err:=q.Snapshot();err==nil {t.Fatal("unsafe legacy envelope entered inventory")}
   if err:=q.ProcessDue(context.Background());err==nil || sends!=0 {t.Fatalf("unsafe legacy mail relayed: %v sends=%d",err,sends)}
   if _,err:=os.Stat(path);err!=nil {t.Fatalf("original removed: %v",err)}
   if _,err:=NewDeliveryQueue(dir,store,func(context.Context,core.Message,[]byte)error{return nil});err==nil {t.Fatal("restart accepted unsafe legacy envelope")}
  })
 }
}
