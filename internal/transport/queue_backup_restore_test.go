package transport

import (
 "bytes"
 "context"
 "path/filepath"
 "testing"
 "time"

 "github.com/gigabytegrove/spamgate/internal/backup"
 "github.com/gigabytegrove/spamgate/internal/core"
)

// Exercise a cold offline backup of an accepted original before the optional
// history mirror is written, then restore into a new data root and relay it.
func TestColdBackupRestoresDurableAcceptedOriginalAndScan(t *testing.T) {
 root := t.TempDir()
 data := filepath.Join(root, "original-data")
 store, err := core.Open(data)
 if err != nil { t.Fatal(err) }
 raw := []byte("From: sender@example.org\r\nTo: recipient@example.net\r\nSubject: backup recovery\r\n\r\nimportant original\r\n")
 msg := core.Message{
  ID:core.ID(), Timestamp:time.Now().UTC(), Sender:"sender@example.org",
  Recipients:[]string{"recipient@example.net"}, Action:"tag", Score:8.5,
  Findings:[]core.Finding{{Symbol:"BACKUP_RECOVERY_TEST", Source:"test", Score:8.5}},
  Connector:"smtp", Delivery:"queued",
 }
 queue, err := NewDeliveryQueue(data, store, func(context.Context, core.Message, []byte) error {
  t.Fatal("offline backup must not trigger delivery")
  return nil
 })
 if err != nil { t.Fatal(err) }
 if err := queue.Enqueue(msg, raw); err != nil { t.Fatal(err) }
 archive := filepath.Join(root, "offline-backup.zip")
 if err := backup.Create(data, archive); err != nil { t.Fatal(err) }
 manifest, err := backup.Verify(archive)
 if err != nil || len(manifest.Entries) == 0 { t.Fatalf("backup not verifiable: %+v %v", manifest, err) }
 restored := filepath.Join(root, "restored-data")
 if err := backup.Restore(archive, restored); err != nil { t.Fatal(err) }
 restoredStore, err := core.Open(restored)
 if err != nil { t.Fatal(err) }
 attempts := 0
 restoredQueue, err := NewDeliveryQueue(restored, restoredStore, func(_ context.Context, m core.Message, b []byte) error {
  attempts++
  if m.ID != msg.ID || m.Action != "tag" || m.Score != msg.Score || len(m.Findings) != 1 ||
   m.Recipients[0] != "recipient@example.net" || !bytes.Equal(b, raw) {
   t.Fatalf("restored original or verdict changed: %+v, raw=%q", m, b)
  }
  return nil
 })
 if err != nil { t.Fatal(err) }
 if err := restoredQueue.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
 if attempts != 1 { t.Fatalf("expected one relay attempt, got %d", attempts) }
 summary, err := restoredQueue.Snapshot()
 if err != nil || summary.Total != 0 { t.Fatalf("restored queue not finalized: %+v %v", summary, err) }
 persisted, err := core.Open(restored)
 if err != nil { t.Fatal(err) }
 result, ok := persisted.Get(msg.ID)
 if !ok || result.Delivery != "relayed" || result.Action != "tag" || result.Score != msg.Score {
  t.Fatalf("restored history lost evidence: %+v, found=%v", result, ok)
 }
}
