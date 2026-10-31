package server

import (
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "testing"
    "time"
)

func TestMonitorPostRenameSyncFailureFreezesUntilRecovery(t *testing.T) {
    root := t.TempDir()
    m := newOperationsMonitor(root)
    now := time.Date(2026, 10, 30, 22, 0, 0, 0, time.UTC)
    first := monitorSample{At: now, BootID: m.bootID, ScanTotal: 1}
    if err := m.record(first); err != nil { t.Fatal(err) }

    m.syncDirectory = func(string) error { return errors.New("injected directory fsync failure") }
    second := monitorSample{At: now.Add(time.Minute), BootID: m.bootID, ScanTotal: 2}
    if err := m.record(second); err == nil || !strings.Contains(err.Error(), "sync unconfirmed") {
        t.Fatalf("post-publication fsync failure was not reported: %v", err)
    }
    raw, err := os.ReadFile(m.path)
    if err != nil { t.Fatal(err) }
    var persisted monitorState
    if err := json.Unmarshal(raw, &persisted); err != nil { t.Fatal(err) }
    if len(persisted.Samples) != 2 || persisted.Samples[1].ScanTotal != 2 {
        t.Fatalf("rename publication missing after injected fsync failure: %+v", persisted)
    }
    if _, err := m.snapshot(); err == nil { t.Fatal("unconfirmed history exposed as healthy") }
    if err := m.record(monitorSample{At: now.Add(2*time.Minute), BootID: m.bootID}); err == nil {
        t.Fatal("stale in-memory history was allowed to overwrite published evidence")
    }

    // A restart reads the authoritative on-disk state before writes resume.
    recovered := newOperationsMonitor(root)
    state, err := recovered.snapshot()
    if err != nil { t.Fatal(err) }
    if len(state.Samples) != 2 || state.Samples[1].ScanTotal != 2 {
        t.Fatalf("restart did not recover published evidence: %+v", state)
    }
    if err := recovered.record(monitorSample{At: now.Add(2*time.Minute), BootID: recovered.bootID, ScanTotal: 3}); err != nil {
        t.Fatal(err)
    }
    final := newOperationsMonitor(root)
    state, err = final.snapshot()
    if err != nil || len(state.Samples) != 3 {
        t.Fatalf("recovered monitor cannot append safely: %+v %v", state, err)
    }
}

func TestMonitorAcknowledgementSyncFailureCannotReportSuccess(t *testing.T) {
    root := t.TempDir()
    m := newOperationsMonitor(root)
    now := time.Date(2026, 10, 30, 22, 5, 0, 0, time.UTC)
    if err := m.record(monitorSample{At: now, BootID: m.bootID, QueueEnabled: true, QueueAvailable: true, QueueDead: 1}); err != nil {
        t.Fatal(err)
    }
    state, err := m.snapshot()
    if err != nil || len(state.Alerts) != 1 { t.Fatalf("expected alert: %+v %v", state, err) }
    id := state.Alerts[0].ID
    m.syncDirectory = func(string) error { return errors.New("injected directory fsync failure") }
    if err := m.acknowledge(id, "admin", "inspected Postfix queue and logs"); err == nil {
        t.Fatal("acknowledgement falsely reported durable success")
    }
    if err := m.acknowledge(id, "admin", "attempted another acknowledgement"); err == nil {
        t.Fatal("unconfirmed history accepted another mutation")
    }
    recovered := newOperationsMonitor(root)
    state, err = recovered.snapshot()
    if err != nil { t.Fatal(err) }
    if len(state.Alerts) != 1 || state.Alerts[0].AcknowledgedBy != "admin" ||
        state.Alerts[0].AcknowledgedAt == nil {
        t.Fatalf("published acknowledgement not recovered: %+v", state.Alerts)
    }
}

func TestMonitorRefusesWritableOperationsDirectory(t *testing.T) {
    if runtime.GOOS == "windows" { t.Skip("POSIX mode enforcement") }
    root := t.TempDir()
    path := filepath.Join(root, "operations")
    if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
    if err := os.Chmod(path, 0777); err != nil { t.Fatal(err) }
    m := newOperationsMonitor(root)
    if _, err := m.snapshot(); err == nil || !strings.Contains(err.Error(), "group/world writable") {
        t.Fatalf("unsafe operations directory accepted: %v", err)
    }
    if err := m.record(monitorSample{At: time.Now()}); err == nil {
        t.Fatal("monitor wrote into unsafe operations directory")
    }
    if _, err := os.Stat(filepath.Join(path, "monitor.json")); !errors.Is(err, os.ErrNotExist) {
        t.Fatalf("unsafe monitor file created: %v", err)
    }
}
