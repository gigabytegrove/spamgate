package server

import (
    "context"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/gigabytegrove/spamgate/internal/core"
    "github.com/gigabytegrove/spamgate/internal/transport"
)

func TestMonitorQueueAlertsSurviveUnavailableInventoryAndRestart(t *testing.T) {
    root := t.TempDir()
    m := newOperationsMonitor(root)
    at := time.Date(2026, 11, 1, 13, 0, 0, 0, time.UTC)
    bad := monitorSample{At: at, BootID: m.bootID, QueueEnabled: true, QueueAvailable: true,
        QueueDead: 2, QueuePendingTemps: 1, QueuePendingTempBytes: 800,
        QueueDiscardPending: 1, QueueQueued: 60, QueueDelivering: 45, QueueDueJobs: 30}
    if err := m.record(bad); err != nil { t.Fatal(err) }
    state, err := m.snapshot()
    if err != nil { t.Fatal(err) }
    for _, code := range []string{"queue_dead", "queue_unpublished_spool", "queue_discard_pending", "queue_backlog", "queue_due_jobs"} {
        if !monitorHasAlert(state, code, "open") { t.Fatalf("missing %s: %+v", code, state.Alerts) }
    }
    if err := m.record(monitorSample{At: at.Add(time.Minute), BootID: m.bootID,
        QueueEnabled: true, QueueAvailable: false}); err != nil { t.Fatal(err) }
    restarted := newOperationsMonitor(root)
    state, err = restarted.snapshot()
    if err != nil { t.Fatal(err) }
    if !monitorHasAlert(state, "queue_unreadable", "open") { t.Fatal("unreadable inventory not alerted") }
    for _, code := range []string{"queue_dead", "queue_unpublished_spool", "queue_discard_pending", "queue_backlog", "queue_due_jobs"} {
        if !monitorHasAlert(state, code, "open") { t.Fatalf("%s falsely resolved on unreadable queue", code) }
    }
    // A disabled outbox also cannot establish that the missing originals were repaired.
    if err := restarted.record(monitorSample{At: at.Add(2*time.Minute), BootID: restarted.bootID}); err != nil { t.Fatal(err) }
    state, err = restarted.snapshot()
    if err != nil { t.Fatal(err) }
    if !monitorHasAlert(state, "queue_dead", "open") || !monitorHasAlert(state, "queue_unreadable", "open") {
        t.Fatal("disabled outbox silently cleared unresolved queue evidence")
    }
    // An actual readable, clean inventory is the only permitted resolution.
    if err := restarted.record(monitorSample{At: at.Add(3*time.Minute), BootID: restarted.bootID,
        QueueEnabled: true, QueueAvailable: true}); err != nil { t.Fatal(err) }
    final := newOperationsMonitor(root)
    state, err = final.snapshot()
    if err != nil { t.Fatal(err) }
    for _, code := range []string{"queue_dead", "queue_unpublished_spool", "queue_discard_pending", "queue_backlog", "queue_due_jobs", "queue_unreadable"} {
        if !monitorHasAlert(state, code, "resolved") { t.Fatalf("%s not resolved after healthy inventory: %+v", code, state.Alerts) }
    }
}

func monitorHasAlert(state monitorState, code, status string) bool {
    for _, alert := range state.Alerts {
        if alert.Code == code && alert.State == status { return true }
    }
    return false
}

func TestMonitorCaptureRecordsRealPendingDiscardAndDueQueue(t *testing.T) {
    store, err := core.Open(t.TempDir())
    if err != nil { t.Fatal(err) }
    s := New(store, nil)
    q, err := transport.NewDeliveryQueue(store.DataDir(), store,
        func(context.Context, core.Message, []byte) error {
            t.Fatal("monitoring must not relay messages")
            return nil
        })
    if err != nil { t.Fatal(err) }
    s.Queue = q
    id := core.ID()
    if err := q.Enqueue(core.Message{ID: id, Sender: "private@example.invalid",
        Recipients: []string{"recipient@example.invalid"}}, []byte("Subject: private\r\n\r\nsecret")); err != nil { t.Fatal(err) }
    if err := os.Mkdir(filepath.Join(store.DataDir(), "events.jsonl"), 0700); err != nil { t.Fatal(err) }
    if err := q.DiscardWithAudit(id, "admin"); err == nil { t.Fatal("expected journal failure") }
    if err := s.monitorCapture(); err != nil { t.Fatal(err) }
    state, err := s.monitor.snapshot()
    if err != nil { t.Fatal(err) }
    latest := state.Samples[len(state.Samples)-1]
    if !latest.QueueAvailable || latest.QueueDiscardPending != 1 || latest.QueueQueued != 0 {
        t.Fatalf("pending discard was not captured: %+v", latest)
    }
    if !monitorHasAlert(state, "queue_discard_pending", "open") { t.Fatal("missing pending-discard alert") }
    raw, err := os.ReadFile(s.monitor.path)
    if err != nil { t.Fatal(err) }
    for _, secret := range []string{id, "private@example.invalid", "recipient@example.invalid", "secret"} {
        if strings.Contains(string(raw), secret) { t.Fatalf("private message data leaked to monitoring: %q", secret) }
    }
}

func TestMonitorRejectsAmbiguousHistoryWithoutOverwritingEvidence(t *testing.T) {
    root := t.TempDir()
    path := filepath.Join(root, "operations", "monitor.json")
    if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { t.Fatal(err) }
    original := []byte(`{"schema":1,"schema":1,"samples":[],"alerts":[]}`)
    if err := os.WriteFile(path, original, 0600); err != nil { t.Fatal(err) }
    m := newOperationsMonitor(root)
    if _, err := m.snapshot(); err == nil || !strings.Contains(err.Error(), "ambiguous operations history") {
        t.Fatalf("duplicate JSON keys accepted: %v", err)
    }
    if err := m.record(monitorSample{At: time.Now()}); err == nil { t.Fatal("ambiguous evidence overwritten") }
    after, err := os.ReadFile(path)
    if err != nil || string(after) != string(original) { t.Fatalf("forensic original changed: %q %v", after, err) }
}
