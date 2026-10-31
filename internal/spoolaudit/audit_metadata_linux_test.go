//go:build linux

package spoolaudit

import (
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestAuditRejectsHardlinkedPublishedOriginalAndRecovers(t *testing.T) {
    dir := privateDir(t)
    path := filepath.Join(dir, idA+".json")
    write(t, dir, idA+".json", fixture(idA))
    alias := filepath.Join(t.TempDir(), "alias")
    if err := os.Link(path, alias); err != nil { t.Fatal(err) }
    report, err := Audit(dir)
    if err != nil || !hasCode(report, "unreadable_record") || report.States["queued"] != 0 {
        t.Fatalf("hardlinked original passed forensic audit: %+v %v", report, err)
    }
    if !strings.Contains(report.Findings[0].Detail, "hard link") {
        t.Fatalf("missing hardlink reason: %+v", report.Findings)
    }
    if err := os.Remove(alias); err != nil { t.Fatal(err) }
    report, err = Audit(dir)
    if err != nil || report.HasFindings() || report.States["queued"] != 1 {
        t.Fatalf("safe original not recognized after repair: %+v %v", report, err)
    }
}

func TestAuditRejectsExposedPublishedAndPendingOriginals(t *testing.T) {
    dir := privateDir(t)
    write(t, dir, idA+".json", fixture(idA))
    write(t, dir, ".pending-unpublished", fixture(idB))
    for _, name := range []string{idA+".json", ".pending-unpublished"} {
        if err := os.Chmod(filepath.Join(dir, name), 0644); err != nil { t.Fatal(err) }
    }
    report, err := Audit(dir)
    if err != nil || report.Published != 1 || report.Pending != 1 {
        t.Fatalf("unexpected inventory: %+v %v", report, err)
    }
    unreadable := 0
    for _, f := range report.Findings {
        if f.Code == "unreadable_record" && strings.Contains(f.Detail, "private") { unreadable++ }
    }
    if unreadable != 2 { t.Fatalf("exposed originals not flagged: %+v", report.Findings) }
    raw, err := json.Marshal(report)
    if err != nil { t.Fatal(err) }
    if strings.Contains(string(raw), "sensitive@example.invalid") || strings.Contains(string(raw), "Confidential") {
        t.Fatal("forensic findings leaked original message content")
    }
}
