package transport

import (
    "context"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "testing"

    "github.com/gigabytegrove/spamgate/internal/core"
)

func TestQueueInventoryBoundsUnrelatedDirectoryEntries(t *testing.T) {
    q, _, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error { return nil })
    for i := 0; i < 4096; i++ {
        path := filepath.Join(q.dir, "unrelated-"+strconv.Itoa(i))
        if err := os.WriteFile(path, nil, 0600); err != nil { t.Fatal(err) }
    }
    summary, err := q.Snapshot()
    if err != nil || summary.Total != 0 { t.Fatalf("valid bounded inventory: %+v %v", summary, err) }
    if err := os.WriteFile(filepath.Join(q.dir, "unrelated-over-limit"), nil, 0600); err != nil { t.Fatal(err) }
    if _, err := q.Snapshot(); err == nil || !strings.Contains(err.Error(), "4096 entries") {
        t.Fatalf("expected bounded inventory refusal, got %v", err)
    }
}

func TestQueueRejectsNegativeAttemptCounter(t *testing.T) {
    q, _, _ := newRecoveryQueue(t, func(context.Context, core.Message, []byte) error { return nil })
    id := core.ID()
    msg := core.Message{ID:id, Sender:"from@example.invalid", Recipients:[]string{"to@example.invalid"}}
    if err := q.Enqueue(msg, []byte("Subject: original\r\n\r\nbody")); err != nil { t.Fatal(err) }
    rec, err := q.get(id)
    if err != nil { t.Fatal(err) }
    rec.Attempts = -1
    // The write itself is structurally valid; the reader must refuse the
    // impossible negative retry count even when digests are recomputed.
    if err := q.put(rec); err != nil { t.Fatal(err) }
    if _, err := q.get(id); err == nil { t.Fatal("accepted negative delivery attempt counter") }
    if _, err := q.Snapshot(); err == nil { t.Fatal("inventory concealed invalid attempt counter") }
}
