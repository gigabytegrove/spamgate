package backup

import (
    "archive/zip"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
)

var ephemeralLockPaths = []string{
    ".worker.lock",
    ".events-journal.lock",
    ".postfix-hold-release.lock",
    "delivery-queue/.delivery-worker.lock",
    "delivery-queue/.delivery-intake.lock",
}

func TestRuntimeLockPathsAreExact(t *testing.T) {
    for _, name := range ephemeralLockPaths {
        if !runtimeLockPath(name) { t.Fatalf("runtime lock not recognized: %q", name) }
    }
    for _, name := range []string{
        "delivery-queue/.pending-surviving-original",
        "delivery-queue/0123456789abcdef0123456789abcdef.json",
        "archive/.worker.lock",
        ".worker.lock.bak",
        "operations/monitor.json",
    } {
        if runtimeLockPath(name) { t.Fatalf("persistent file excluded: %q", name) }
    }
}

func TestColdBackupOmitsRuntimeLocksButPreservesOriginals(t *testing.T) {
    root := t.TempDir()
    source := filepath.Join(root, "data")
    if err := os.MkdirAll(filepath.Join(source, "delivery-queue"), 0700); err != nil { t.Fatal(err) }
    keep := map[string]string{
        "config.json": "{\"settings\":{}}",
        "delivery-queue/.pending-forensic-original": "never discard this evidence",
        "delivery-queue/0123456789abcdef0123456789abcdef.json": "retained mail original",
        "operations/monitor.json": "{\"healthy\":true}",
    }
    for name, body := range keep {
        path := filepath.Join(source, filepath.FromSlash(name))
        if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { t.Fatal(err) }
        if err := os.WriteFile(path, []byte(body), 0600); err != nil { t.Fatal(err) }
    }
    for _, name := range ephemeralLockPaths {
        path := filepath.Join(source, filepath.FromSlash(name))
        if err := os.WriteFile(path, []byte("stale lock from previous worker"), 0600); err != nil { t.Fatal(err) }
    }
    archive := filepath.Join(root, "cold.zip")
    if err := Create(source, archive); err != nil { t.Fatal(err) }
    manifest, err := Verify(archive)
    if err != nil { t.Fatal(err) }
    got := make(map[string]bool)
    for _, entry := range manifest.Entries {
        if runtimeLockPath(entry.Path) { t.Fatalf("new backup included runtime lock %q", entry.Path) }
        got[entry.Path] = true
    }
    for name := range keep {
        if !got[name] { t.Fatalf("backup lost persistent data %q", name) }
    }
    dest := filepath.Join(root, "restored")
    if err := Restore(archive, dest); err != nil { t.Fatal(err) }
    for _, name := range ephemeralLockPaths {
        if _, err := os.Lstat(filepath.Join(dest, filepath.FromSlash(name))); !os.IsNotExist(err) {
            t.Fatalf("restored stale runtime lock %q: %v", name, err)
        }
    }
    for name, want := range keep {
        b, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(name)))
        if err != nil || string(b) != want { t.Fatalf("lost %q: %q %v", name, b, err) }
    }
}

func TestLegacyArchiveRuntimeLocksVerifiedButNotRestored(t *testing.T) {
    root := t.TempDir()
    archive := filepath.Join(root, "legacy.zip")
    f, err := os.Create(archive)
    if err != nil { t.Fatal(err) }
    zw := zip.NewWriter(f)
    contents := map[string]string{"config.json": "persistent configuration"}
    for _, name := range ephemeralLockPaths { contents[name] = "old-worker-lock" }
    manifest := Manifest{Format: 1, Product: "SpamGate"}
    for name, body := range contents {
        w, err := zw.Create(name)
        if err != nil { t.Fatal(err) }
        if _, err := w.Write([]byte(body)); err != nil { t.Fatal(err) }
        digest := sha256.Sum256([]byte(body))
        manifest.Entries = append(manifest.Entries, Entry{
            Path: name, Bytes: int64(len(body)), SHA256: hex.EncodeToString(digest[:]),
        })
    }
    w, err := zw.Create(manifestPath)
    if err != nil { t.Fatal(err) }
    if err := json.NewEncoder(w).Encode(manifest); err != nil { t.Fatal(err) }
    if err := zw.Close(); err != nil { t.Fatal(err) }
    if err := f.Close(); err != nil { t.Fatal(err) }
    if _, err := Verify(archive); err != nil { t.Fatal(err) }
    dest := filepath.Join(root, "restored")
    if err := Restore(archive, dest); err != nil { t.Fatal(err) }
    b, err := os.ReadFile(filepath.Join(dest, "config.json"))
    if err != nil || string(b) != contents["config.json"] { t.Fatalf("persistent data missing: %q %v", b, err) }
    for _, name := range ephemeralLockPaths {
        if _, err := os.Lstat(filepath.Join(dest, filepath.FromSlash(name))); !os.IsNotExist(err) {
            t.Fatalf("legacy runtime lock was restored %q: %v", name, err)
        }
    }
}

func TestBackupRejectsMasqueradingRuntimeLocks(t *testing.T) {
    for _, kind := range []string{"directory", "symlink"} {
        t.Run(kind, func(t *testing.T) {
            root := t.TempDir()
            source := filepath.Join(root, "data")
            if err := os.MkdirAll(filepath.Join(source, "delivery-queue"), 0700); err != nil { t.Fatal(err) }
            if err := os.WriteFile(filepath.Join(source, "config.json"), []byte("{}"), 0600); err != nil { t.Fatal(err) }
            path := filepath.Join(source, "delivery-queue", ".delivery-worker.lock")
            if kind == "directory" {
                if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
            } else {
                if err := os.Symlink(filepath.Join(root, "outside"), path); err != nil { t.Skip(err) }
            }
            archive := filepath.Join(root, "refused.zip")
            if err := Create(source, archive); err == nil { t.Fatal("masked unsafe lock inode") }
            if _, err := os.Lstat(archive); !os.IsNotExist(err) {
                t.Fatalf("unsafe backup was published: %v", err)
            }
        })
    }
}
