package server

import (
    "errors"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "testing"
    "time"
)

func TestMonitorRefusesSymlinkedHistoryAndDoesNotOverwriteTarget(t *testing.T) {
    if runtime.GOOS == "windows" { t.Skip("symlink creation needs elevated Windows privileges") }
    root := t.TempDir()
    operations := filepath.Join(root, "operations")
    if err := os.Mkdir(operations, 0700); err != nil { t.Fatal(err) }
    target := filepath.Join(t.TempDir(), "sensitive.txt")
    if err := os.WriteFile(target, []byte("preserve outside target"), 0600); err != nil { t.Fatal(err) }
    if err := os.Symlink(target, filepath.Join(operations, "monitor.json")); err != nil { t.Fatal(err) }
    m := newOperationsMonitor(root)
    if _, err := m.snapshot(); err == nil { t.Fatal("symlinked history was accepted") }
    if err := m.record(monitorSample{At: time.Now()}); err == nil { t.Fatal("symlinked history was overwritten") }
    got, err := os.ReadFile(target)
    if err != nil || string(got) != "preserve outside target" {
        t.Fatalf("external target changed: %q %v", got, err)
    }
}

func TestMonitorRefusesSymlinkedOperationsDirectory(t *testing.T) {
    if runtime.GOOS == "windows" { t.Skip("symlink creation needs elevated Windows privileges") }
    root := t.TempDir()
    external := t.TempDir()
    if err := os.Symlink(external, filepath.Join(root, "operations")); err != nil { t.Fatal(err) }
    m := newOperationsMonitor(root)
    if _, err := m.snapshot(); err == nil { t.Fatal("symlinked operations directory accepted") }
    if err := m.record(monitorSample{At: time.Now()}); err == nil { t.Fatal("symlinked operations directory accepted for writing") }
    if _, err := os.Stat(filepath.Join(external, "monitor.json")); !errors.Is(err, os.ErrNotExist) {
        t.Fatalf("external operations directory modified: %v", err)
    }
}

func TestMonitorRejectsOversizedSparseHistoryWithoutOverwriting(t *testing.T) {
    root := t.TempDir()
    dir := filepath.Join(root, "operations")
    if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
    path := filepath.Join(dir, "monitor.json")
    f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
    if err != nil { t.Fatal(err) }
    if err := f.Truncate((2<<20)+1); err != nil { f.Close(); t.Fatal(err) }
    if err := f.Close(); err != nil { t.Fatal(err) }
    m := newOperationsMonitor(root)
    if _, err := m.snapshot(); err == nil || !strings.Contains(err.Error(), "2 MiB") {
        t.Fatalf("oversized history not reported: %v", err)
    }
    if err := m.record(monitorSample{At: time.Now()}); err == nil {
        t.Fatal("oversized history was silently overwritten")
    }
    stat, err := os.Stat(path)
    if err != nil || stat.Size() != (2<<20)+1 {
        t.Fatalf("forensic history changed: %+v %v", stat, err)
    }
}

func TestMonitorRegularHistoryRemainsReadableAcrossRestart(t *testing.T) {
    root := t.TempDir()
    m := newOperationsMonitor(root)
    if err := m.record(monitorSample{At: time.Now().UTC(), BootID: m.bootID, ScanTotal: 42}); err != nil {
        t.Fatal(err)
    }
    next := newOperationsMonitor(root)
    state, err := next.snapshot()
    if err != nil { t.Fatal(err) }
    if len(state.Samples) != 1 || state.Samples[0].ScanTotal != 42 {
        t.Fatalf("regular history migration regression: %+v", state)
    }
}
