package spoolaudit

import (
    "bytes"
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

// A Unicode SimpleFold alias of "state" is decoded by encoding/json as the
// same struct field. The previous ToLower-only duplicate check missed it.
func TestAuditRejectsUnicodeFoldedStateWithMatchingDigests(t *testing.T) {
    dir := privateDir(t)
    original, err := json.Marshal(fixture(idA))
    if err != nil { t.Fatal(err) }
    old := []byte(`"state":"queued"`)
    if !bytes.Contains(original, old) { t.Fatal("fixture missing queued state") }
    altered := bytes.Replace(original, old, []byte(`"ſtate":"dead","state":"queued"`), 1)
    var decoded record
    if err := json.Unmarshal(altered, &decoded); err != nil { t.Fatal(err) }
    if decoded.State != "queued" || decoded.IntegritySHA256 != immutableDigest(decoded) ||
        decoded.StateSHA256 != stateDigest(decoded) {
        t.Fatal("fixture did not reproduce matching-digest Unicode key ambiguity")
    }
    path := filepath.Join(dir, idA+".json")
    if err := os.WriteFile(path, altered, 0600); err != nil { t.Fatal(err) }
    report, err := Audit(dir)
    if err != nil { t.Fatal(err) }
    if !hasCode(report, "unreadable_record") || report.States["queued"] != 0 {
        t.Fatalf("ambiguous Unicode spool passed forensic audit: %+v", report)
    }
    if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Detail, "duplicate") {
        t.Fatalf("missing Unicode duplicate finding: %+v", report.Findings)
    }
    after, err := os.ReadFile(path)
    if err != nil || !bytes.Equal(after, altered) {
        t.Fatalf("forensic audit modified original: %v", err)
    }
}
