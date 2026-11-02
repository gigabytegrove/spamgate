package backup

import (
    "archive/zip"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

// A ZIP with correct payload hashes must still be rejected if its manifest
// has ambiguous JSON keys, invalid Unicode, trailing values or unknown
// fields. Verify and Restore share this exact trust boundary.
func TestBackupManifestRejectsAmbiguousJSONBeforeRestore(t *testing.T) {
    payload := []byte("{\"setup_complete\":true}\n")
    digest := sha256.Sum256(payload)
    valid := fmt.Sprintf(`{"format":1,"created":"2026-11-02T08:00:00Z","product":"SpamGate","entries":[{"path":"config.json","bytes":%d,"sha256":"%s"}]}`, len(payload), hex.EncodeToString(digest[:]))
    cases := []struct {
        name, manifest string
    }{
        {"duplicate root", strings.Replace(valid, `"product":"SpamGate"`, `"product":"SpamGate","product":"Other"`, 1)},
        {"case folded root", strings.Replace(valid, `"product":"SpamGate"`, `"product":"SpamGate","Product":"Other"`, 1)},
        {"escaped root alias", strings.Replace(valid, `"product":"SpamGate"`, `"product":"SpamGate","pr\u006fduct":"Other"`, 1)},
        {"duplicate nested path", strings.Replace(valid, `"path":"config.json"`, `"path":"config.json","Path":"other"`, 1)},
        {"duplicate nested size", strings.Replace(valid, `"bytes":`+fmt.Sprint(len(payload)), `"bytes":`+fmt.Sprint(len(payload))+`,"Bytes":`+fmt.Sprint(len(payload)+1), 1)},
        {"Unicode folded nested size", strings.Replace(valid, `"bytes":`+fmt.Sprint(len(payload)), `"bytes":`+fmt.Sprint(len(payload))+`,"byte\u017f":`+fmt.Sprint(len(payload)+1), 1)},
        {"unknown root field", strings.Replace(valid, `"product":"SpamGate"`, `"product":"SpamGate","unreviewed":true`, 1)},
        {"unknown entry field", strings.Replace(valid, `"path":"config.json"`, `"path":"config.json","unreviewed":true`, 1)},
        {"unpaired high surrogate", strings.Replace(valid, `"product":"SpamGate"`, `"product":"SpamGate","extra":"\ud800"`, 1)},
        {"unpaired low surrogate", strings.Replace(valid, `"product":"SpamGate"`, `"product":"SpamGate","extra":"\udc00"`, 1)},
        {"trailing object", valid + ` {}`},
        {"invalid utf8", strings.Replace(valid, `"product":"SpamGate"`, "\"product\":\"SpamGate\",\"extra\":\""+string([]byte{0xff})+"\"", 1)},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            root := t.TempDir()
            archive := filepath.Join(root, "forged.zip")
            if err := writeManifestFixture(archive, payload, []byte(tc.manifest)); err != nil { t.Fatal(err) }
            if _, err := Verify(archive); err == nil {
                t.Fatal("ambiguous or malformed manifest passed verification")
            }
            dest := filepath.Join(root, "restored")
            if err := Restore(archive, dest); err == nil {
                t.Fatal("ambiguous or malformed manifest was restored")
            }
            if _, err := os.Lstat(dest); !os.IsNotExist(err) {
                t.Fatalf("invalid backup published restore destination: %v", err)
            }
        })
    }
    t.Run("valid v1 manifest", func(t *testing.T) {
        root := t.TempDir()
        archive := filepath.Join(root, "valid.zip")
        if err := writeManifestFixture(archive, payload, []byte(valid)); err != nil { t.Fatal(err) }
        if _, err := Verify(archive); err != nil { t.Fatalf("valid backup refused: %v", err) }
        dest := filepath.Join(root, "restored")
        if err := Restore(archive, dest); err != nil { t.Fatalf("valid restore refused: %v", err) }
        got, err := os.ReadFile(filepath.Join(dest, "config.json"))
        if err != nil || string(got) != string(payload) { t.Fatalf("restored content mismatch: %q %v", got, err) }
    })
}

func writeManifestFixture(path string, payload, manifest []byte) error {
    f, err := os.Create(path)
    if err != nil { return err }
    zw := zip.NewWriter(f)
    for _, entry := range []struct{name string; content []byte}{
        {"config.json", payload}, {manifestPath, manifest},
    } {
        w, err := zw.Create(entry.name)
        if err != nil { zw.Close(); f.Close(); return err }
        if _, err := w.Write(entry.content); err != nil { zw.Close(); f.Close(); return err }
    }
    if err := zw.Close(); err != nil { f.Close(); return err }
    return f.Close()
}
