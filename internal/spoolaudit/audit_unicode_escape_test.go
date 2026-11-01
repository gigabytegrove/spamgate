package spoolaudit

import (
    "bytes"
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestAuditRejectsLossyUnicodeEscapeWithoutRewritingOriginal(t *testing.T) {
    dir := privateDir(t)
    rec := fixture(idA)
    rec.Subject = "replacement \ufffd character"
    rec.StateSHA256 = stateDigest(rec)
    canonical, err := json.Marshal(rec)
    if err != nil { t.Fatal(err) }
    malformed := bytes.Replace(canonical, []byte("replacement \ufffd character"), []byte(`replacement \ud800 character`), 1)
    if bytes.Equal(canonical, malformed) { t.Fatal("fixture mutation did not occur") }
    var decoded record
    if err := json.Unmarshal(malformed, &decoded); err != nil { t.Fatal(err) }
    if decoded.Subject != rec.Subject || stateDigest(decoded) != decoded.StateSHA256 || immutableDigest(decoded) != decoded.IntegritySHA256 {
        t.Fatal("fixture did not preserve decoded values and digests")
    }
    path := filepath.Join(dir, idA+".json")
    if err := os.WriteFile(path, malformed, 0600); err != nil { t.Fatal(err) }
    report, err := Audit(dir)
    if err != nil { t.Fatal(err) }
    if !hasCode(report, "unreadable_record") || report.States["queued"] != 0 {
        t.Fatalf("auditor accepted lossy Unicode: %+v", report)
    }
    if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Detail, "Unicode escape") {
        t.Fatalf("auditor did not identify malformed Unicode: %+v", report.Findings)
    }
    preserved, err := os.ReadFile(path)
    if err != nil || !bytes.Equal(preserved, malformed) { t.Fatalf("audit modified original: %v", err) }
}
