package spoolaudit

import (
    "bytes"
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestAuditRejectsDuplicateKeysWithMatchingDecodedDigest(t *testing.T) {
    dir := privateDir(t)
    rec := fixture(idA)
    b, err := json.Marshal(rec)
    if err != nil { t.Fatal(err) }
    old := []byte(`"state":"queued"`)
    if !bytes.Contains(b, old) { t.Fatal("fixture missing state") }
    ambiguous := bytes.Replace(b, old, []byte(`"state":"dead","state":"queued"`), 1)
    path := filepath.Join(dir, idA+".json")
    if err := os.WriteFile(path, ambiguous, 0600); err != nil { t.Fatal(err) }
    report, err := Audit(dir)
    if err != nil { t.Fatal(err) }
    if !hasCode(report, "unreadable_record") || report.States["queued"] != 0 {
        t.Fatalf("ambiguous spool considered valid: %+v", report)
    }
    if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Detail, "duplicate") {
        t.Fatalf("missing duplicate-key explanation: %+v", report.Findings)
    }
    if _, err := os.Stat(path); err != nil { t.Fatalf("read-only audit changed spool: %v", err) }
}
