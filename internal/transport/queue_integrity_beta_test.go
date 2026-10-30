package transport

import (
 "context"
 "os"
 "path/filepath"
 "strings"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/core"
)

func newIntegrityQueue(t *testing.T) (*DeliveryQueue, *core.Store, string) {
 t.Helper()
 dir := t.TempDir()
 store, err := core.Open(dir)
 if err != nil { t.Fatal(err) }
 q, err := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error { return nil })
 if err != nil { t.Fatal(err) }
 return q, store, dir
}

func TestQueueRejectsPathTraversalIDsBeforeWriting(t *testing.T) {
 q, _, dir := newIntegrityQueue(t)
 for _, id := range []string{"../../escape", strings.Repeat("A", 32), strings.Repeat("0", 31), strings.Repeat("/", 32)} {
  m := core.Message{ID:id, Sender:"a@example.org", Recipients:[]string{"b@example.net"}}
  if err := q.Enqueue(m, []byte("raw")); err == nil { t.Fatalf("accepted unsafe ID %q", id) }
 }
 if _, err := os.Stat(filepath.Join(dir, "escape.json")); !os.IsNotExist(err) { t.Fatalf("unsafe path created: %v", err) }
 s, err := q.Snapshot()
 if err != nil || s.Total != 0 { t.Fatalf("invalid IDs modified spool: %+v %v", s, err) }
}

func TestQueueRejectsTamperedOriginalAndRecipientEnvelope(t *testing.T) {
 q, _, _ := newIntegrityQueue(t)
 id := core.ID()
 m := core.Message{ID:id, Sender:"a@example.org", Recipients:[]string{"b@example.net"}}
 if err := q.Enqueue(m, []byte("Subject: safe\r\n\r\noriginal")); err != nil { t.Fatal(err) }
 rec, err := q.get(id)
 if err != nil || rec.IntegritySHA256 == "" { t.Fatalf("new record missing digest: %v", err) }
 rec.RawRFC822[0] ^= 1
 if err := q.put(rec); err != nil { t.Fatal(err) }
 if _, err := q.Snapshot(); err == nil || !strings.Contains(err.Error(), "integrity") { t.Fatalf("tampered body accepted: %v", err) }
 rec.RawRFC822[0] ^= 1
 rec.Recipients[0] = "attacker@example.net"
 if err := q.put(rec); err != nil { t.Fatal(err) }
 if err := q.ProcessDue(context.Background()); err == nil || !strings.Contains(err.Error(), "integrity") { t.Fatalf("tampered envelope forwarded: %v", err) }
}

func TestLegacySpoolWithoutDigestRemainsRecoverable(t *testing.T) {
 q, _, _ := newIntegrityQueue(t)
 id := core.ID()
 m := core.Message{ID:id, Sender:"a@example.org", Recipients:[]string{"b@example.net"}}
 if err := q.Enqueue(m, []byte("Subject: legacy\r\n\r\nbody")); err != nil { t.Fatal(err) }
 rec, err := q.get(id)
 if err != nil { t.Fatal(err) }
 rec.IntegritySHA256 = ""
 if err := q.put(rec); err != nil { t.Fatal(err) }
 if err := q.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
 s, err := q.Snapshot()
 if err != nil || s.Total != 0 { t.Fatalf("legacy record not delivered: %+v %v", s, err) }
}

func TestQueueRejectsSymlinkAndWorldWritableSpoolDirectory(t *testing.T) {
 dir := t.TempDir()
 store, err := core.Open(dir)
 if err != nil { t.Fatal(err) }
 target := t.TempDir()
 if err := os.Symlink(target, filepath.Join(dir, "delivery-queue")); err != nil { t.Skip(err) }
 if _, err := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error { return nil }); err == nil {
  t.Fatal("followed symlink spool directory")
 }
 if err := os.Remove(filepath.Join(dir, "delivery-queue")); err != nil { t.Fatal(err) }
 if err := os.Mkdir(filepath.Join(dir, "delivery-queue"), 0777); err != nil { t.Fatal(err) }
 if err := os.Chmod(filepath.Join(dir, "delivery-queue"), 0777); err != nil { t.Fatal(err) }
 if _, err := NewDeliveryQueue(dir, store, func(context.Context, core.Message, []byte) error { return nil }); err == nil {
  t.Fatal("accepted world-writable spool directory")
 }
}

func TestAuditedDiscardFailsClosedOnHistoryErrorAndRecordsSuccess(t *testing.T) {
 q, store, dir := newIntegrityQueue(t)
 id := core.ID()
 m := core.Message{ID:id, Sender:"a@example.org", Recipients:[]string{"b@example.net"}}
 if err := q.Enqueue(m, []byte("Subject: discard\r\n\r\noriginal")); err != nil { t.Fatal(err) }
 if err := os.Mkdir(filepath.Join(dir, "events.jsonl"), 0700); err != nil { t.Fatal(err) }
 if err := q.DiscardWithAudit(id, "administrator"); err == nil { t.Fatal("discarded original without durable audit") }
 if _, err := q.get(id); err != nil { t.Fatalf("original lost on audit failure: %v", err) }
 if err := os.Remove(filepath.Join(dir, "events.jsonl")); err != nil { t.Fatal(err) }
 if err := q.DiscardWithAudit(id, "administrator"); err != nil { t.Fatal(err) }
 if _, err := q.get(id); !os.IsNotExist(err) { t.Fatalf("original still present after audited discard: %v", err) }
 got, ok := store.Get(id)
 if !ok || got.Delivery != "discarded" || got.OverrideBy != "administrator" || len(got.Findings) < 2 {
  t.Fatalf("missing final audit: %+v %v", got, ok)
 }
 restarted, err := core.Open(dir)
 if err != nil { t.Fatal(err) }
 persisted, ok := restarted.Get(id)
 if !ok || persisted.Delivery != "discarded" { t.Fatalf("discard audit did not survive restart: %+v", persisted) }
}
