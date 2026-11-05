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
