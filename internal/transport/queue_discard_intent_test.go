package transport

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
 "github.com/gigabytegrove/spamgate/internal/core"
)

func TestDiscardIntentSurvivesAuditOutageAndRestart(t *testing.T) {
 sends := 0
 send := func(context.Context, core.Message, []byte) error { sends++; return nil }
 q, store, dir := newRecoveryQueue(t, send)
 id := core.ID()
 if err := q.Enqueue(core.Message{ID:id, Sender:"sender@example.invalid", Recipients:[]string{"user@example.invalid"}}, []byte("Subject: test\r\n\r\noriginal")); err != nil { t.Fatal(err) }
 journal := filepath.Join(dir,"events.jsonl")
 if err := os.Mkdir(journal,0700); err != nil { t.Fatal(err) }
 if err := q.DiscardWithAudit(id,"admin"); err == nil || !strings.Contains(err.Error(),"unaudited") { t.Fatalf("expected audit failure, got %v",err) }
 state,err := q.Snapshot()
 if err != nil || state.DiscardPending != 1 || state.Total != 1 { t.Fatalf("discard intent missing: %+v %v",state,err) }
 if err := q.Retry(id); err == nil { t.Fatal("retry accepted pending discard") }
 if err := q.Discard(id); err == nil { t.Fatal("unaudited delete accepted pending discard") }
 if err := q.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
 if sends != 0 { t.Fatal("relayed pending discard") }
 if err := os.Remove(journal); err != nil { t.Fatal(err) }
 restarted,err := NewDeliveryQueue(dir,store,send)
 if err != nil { t.Fatal(err) }
 restarted.now = func() time.Time { return time.Now().Add(24*time.Hour) }
 if err := restarted.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
 if sends != 0 { t.Fatal("relayed pending discard after restart") }
 if err := restarted.DiscardWithAudit(id,"admin"); err != nil { t.Fatal(err) }
 state,err = restarted.Snapshot()
 if err != nil || state.Total != 0 { t.Fatalf("discard not finalized: %+v %v",state,err) }
 record,ok := store.Get(id)
 if !ok || record.Delivery != "discarded" { t.Fatalf("missing final audit: %+v %v",record,ok) }
}

func TestLegacyJournalFirstDiscardIsReconciled(t *testing.T) {
 sends := 0
 send := func(context.Context,core.Message,[]byte) error { sends++; return nil }
 q,store,dir := newRecoveryQueue(t,send)
 id := core.ID()
 msg := core.Message{ID:id,Sender:"sender@example.invalid",Recipients:[]string{"user@example.invalid"},Delivery:"discard_requested"}
 if err := q.Enqueue(msg,[]byte("Subject: legacy\r\n\r\noriginal")); err != nil { t.Fatal(err) }
 if err := store.Save(msg); err != nil { t.Fatal(err) }
 if err := q.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
 rec,err := q.get(id)
 if err != nil || rec.State != "discard_pending" || rec.Attempts != 0 { t.Fatalf("legacy intent not reconciled: %+v %v",rec.QueuedMessage,err) }
 if sends != 0 { t.Fatal("relayed legacy pending discard") }
 restarted,err := NewDeliveryQueue(dir,store,send)
 if err != nil { t.Fatal(err) }
 if err := restarted.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
 if sends != 0 { t.Fatal("relayed after restart") }
 if err := restarted.DiscardWithAudit(id,"admin"); err != nil { t.Fatal(err) }
 if _,err := os.Stat(restarted.path(id)); !os.IsNotExist(err) { t.Fatalf("original not removed: %v",err) }
}
