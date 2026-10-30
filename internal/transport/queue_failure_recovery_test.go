package transport

import (
    "context"
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/gigabytegrove/spamgate/internal/core"
)

func newRecoveryQueue(t *testing.T, deliver func(context.Context, core.Message, []byte) error) (*DeliveryQueue, *core.Store, string) {
    t.Helper()
    dir := t.TempDir()
    store, err := core.Open(dir)
    if err != nil { t.Fatal(err) }
    queue, err := NewDeliveryQueue(dir, store, deliver)
    if err != nil { t.Fatal(err) }
    return queue, store, dir
}

func TestJournalOutageDoesNotConsumeDeliveryAttempt(t *testing.T) {
    sends := 0
    q, _, dir := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error {
        sends++
        return nil
    })
    id := core.ID()
    msg := core.Message{ID:id, Sender:"from@example.invalid", Recipients:[]string{"to@example.invalid"}}
    raw := []byte("From: from@example.invalid\r\nTo: to@example.invalid\r\n\r\nhello")
    if err := q.Enqueue(msg, raw); err != nil { t.Fatal(err) }

    // Simulate a history journal that cannot be created. A message already
    // accepted into the durable spool must remain queued without a send.
    journal := filepath.Join(dir, "events.jsonl")
    if err := os.Mkdir(journal, 0700); err != nil { t.Fatal(err) }
    for i := 0; i < 3; i++ {
        if err := q.ProcessDue(context.Background()); err == nil {
            t.Fatal("expected unavailable history journal to stop delivery")
        }
    }
    snapshot, err := q.Snapshot()
    if err != nil { t.Fatal(err) }
    if sends != 0 || snapshot.Queued != 1 || len(snapshot.Jobs) != 1 ||
        snapshot.Jobs[0].Attempts != 0 || snapshot.Jobs[0].State != "queued" {
        t.Fatalf("history outage consumed an attempt or sent mail: sends=%d queue=%+v", sends, snapshot)
    }
    if err := os.Remove(journal); err != nil { t.Fatal(err) }
    if err := q.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
    if sends != 1 { t.Fatalf("expected one relay after journal repair, got %d", sends) }
    snapshot, err = q.Snapshot()
    if err != nil || snapshot.Total != 0 { t.Fatalf("delivery did not finalize: %+v %v", snapshot, err) }
}

func TestEnvelopeCorrectionOutageDoesNotConsumeAttempt(t *testing.T) {
    sends := 0
    q, store, dir := newRecoveryQueue(t, func(_ context.Context, m core.Message, _ []byte) error {
        sends++
        if m.Sender != "authoritative@example.invalid" ||
            len(m.Recipients) != 1 || m.Recipients[0] != "real@example.invalid" {
            t.Errorf("relayed stale history envelope: %+v", m)
        }
        return nil
    })
    id := core.ID()
    stale := core.Message{ID:id, Sender:"stale@example.invalid", Recipients:[]string{"wrong@example.invalid"}, Timestamp:time.Now()}
    if err := store.Save(stale); err != nil { t.Fatal(err) }
    authoritative := core.Message{ID:id, Sender:"authoritative@example.invalid", Recipients:[]string{"real@example.invalid"}}
    if err := q.Enqueue(authoritative, []byte("Subject: original\r\n\r\nbody")); err != nil { t.Fatal(err) }

    journal := filepath.Join(dir, "events.jsonl")
    backup := filepath.Join(dir, "events.jsonl.saved")
    if err := os.Rename(journal, backup); err != nil { t.Fatal(err) }
    if err := os.Mkdir(journal, 0700); err != nil { t.Fatal(err) }
    if err := q.ProcessDue(context.Background()); err == nil {
        t.Fatal("expected envelope correction persistence to fail")
    }
    summary, err := q.Snapshot()
    if err != nil { t.Fatal(err) }
    if sends != 0 || summary.Queued != 1 || summary.Jobs[0].Attempts != 0 {
        t.Fatalf("attempt consumed before envelope repair: %+v, sends=%d", summary, sends)
    }
    if err := os.Remove(journal); err != nil { t.Fatal(err) }
    if err := os.Rename(backup, journal); err != nil { t.Fatal(err) }
    if err := q.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
    if sends != 1 { t.Fatalf("expected exactly one correct relay, got %d", sends) }
    recovered, ok := store.Get(id)
    if !ok || recovered.Sender != authoritative.Sender || recovered.Recipients[0] != authoritative.Recipients[0] {
        t.Fatalf("authoritative envelope not restored: %+v", recovered)
    }
}

func TestSyncedPendingOriginalSurvivesRenameFailure(t *testing.T) {
    q, _, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error { return nil })
    id := core.ID()
    raw := []byte("Subject: durable\r\n\r\noriginal bytes")
    now := time.Now().UTC()
    rec := spoolRecord{
        QueuedMessage: QueuedMessage{
            ID:id, Sender:"sender@example.invalid", Recipients:[]string{"recipient@example.invalid"},
            Created:now, Updated:now, NextAttempt:now, State:"queued", Size:len(raw),
        },
        RawRFC822: raw,
    }
    rec.IntegritySHA256 = spoolDigest(rec)

    // A directory at the final pathname forces rename to fail after the
    // temporary file has been fully written, fsynced and closed.
    if err := os.Mkdir(q.path(id), 0700); err != nil { t.Fatal(err) }
    err := q.put(rec)
    if err == nil || !strings.Contains(err.Error(), "unpublished spool retained") {
        t.Fatalf("expected a visible retained-original failure, got %v", err)
    }
    entries, err := os.ReadDir(q.dir)
    if err != nil { t.Fatal(err) }
    pending := 0
    for _, entry := range entries {
        if !strings.HasPrefix(entry.Name(), ".pending-") { continue }
        pending++
        b, err := os.ReadFile(filepath.Join(q.dir, entry.Name()))
        if err != nil { t.Fatal(err) }
        var saved spoolRecord
        if err := json.Unmarshal(b, &saved); err != nil { t.Fatal(err) }
        if saved.ID != id || string(saved.RawRFC822) != string(raw) ||
            saved.IntegritySHA256 != spoolDigest(saved) ||
            saved.StateSHA256 != spoolStateDigest(saved) {
            t.Fatalf("unpublished original is incomplete or corrupt: %+v", saved.QueuedMessage)
        }
    }
    if pending != 1 { t.Fatalf("expected one retained synced pending original, got %d", pending) }
}
