package backup

import (
    "archive/zip"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "math"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestArchiveByteBudgetRejectsOverflow(t *testing.T) {
    for _, pair := range [][2]uint64{
        {uint64(maxBytes), 1},
        {1, uint64(maxBytes)},
        {math.MaxUint64 - 1, 4},
        {0, uint64(maxBytes) + 1},
    } {
        if _, err := addBoundedArchiveBytes(pair[0], pair[1]); err == nil {
            t.Fatalf("accepted over-budget or overflowing total: %v", pair)
        }
    }
    if n, err := addBoundedArchiveBytes(uint64(maxBytes)-1, 1); err != nil || n != uint64(maxBytes) {
        t.Fatalf("rejected exact byte limit: %d %v", n, err)
    }
}

func TestVerifyRejectsConflictingArchivePathsBeforeRestore(t *testing.T) {
    root := t.TempDir()
    archive := filepath.Join(root, "conflict.zip")
    f, err := os.Create(archive)
    if err != nil { t.Fatal(err) }
    zw := zip.NewWriter(f)
    m := Manifest{Format: 1, Product: "SpamGate", Entries: []Entry{}}
    for _, name := range []string{"mail", "mail/queued.eml"} {
        content := []byte("x")
        w, err := zw.Create(name)
        if err != nil { t.Fatal(err) }
        if _, err := w.Write(content); err != nil { t.Fatal(err) }
        digest := sha256.Sum256(content)
        m.Entries = append(m.Entries, Entry{Path: name, Bytes: int64(len(content)), SHA256: hex.EncodeToString(digest[:])})
    }
    w, err := zw.Create(manifestPath)
    if err != nil { t.Fatal(err) }
    if err := json.NewEncoder(w).Encode(m); err != nil { t.Fatal(err) }
    if err := zw.Close(); err != nil { t.Fatal(err) }
    if err := f.Close(); err != nil { t.Fatal(err) }
    if _, err := Verify(archive); err == nil || !strings.Contains(err.Error(), "conflict") {
        t.Fatalf("accepted conflicting archive paths: %v", err)
    }
    dest := filepath.Join(root, "restored")
    if err := Restore(archive, dest); err == nil {
        t.Fatal("restored conflicting archive paths")
    }
    if _, err := os.Lstat(dest); !os.IsNotExist(err) {
        t.Fatalf("published an invalid restore: %v", err)
    }
}

func TestBackupPathRejectsControlCharacters(t *testing.T) {
    for _, name := range []string{"evil\x00file", "mail/evil\nname", "mail/evil\rname", "mail/evil\x7fname"} {
        if safeName(name) { t.Fatalf("accepted unsafe filename %q", name) }
    }
}
