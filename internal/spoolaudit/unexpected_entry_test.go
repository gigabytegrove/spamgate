package spoolaudit

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestAuditReportsUnexpectedDirectoryAndSymlink(t *testing.T) {
 dir := privateDir(t)
 if err := os.Mkdir(filepath.Join(dir, "hidden-tree"), 0700); err != nil { t.Fatal(err) }
 if err := os.Symlink("hidden-tree", filepath.Join(dir, "hidden-link")); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(dir, "operator-note"), []byte("leave intact"), 0600); err != nil { t.Fatal(err) }
 report, err := Audit(dir)
 if err != nil { t.Fatal(err) }
 if report.UnexpectedEntries != 2 || report.Examined != 3 {
  t.Fatalf("unexpected queue object counts: %+v", report)
 }
 if !strings.Contains(report.Explain(), "unexpected_entries=2") { t.Fatal(report.Explain()) }
 if len(report.Findings) != 2 { t.Fatalf("findings: %+v", report.Findings) }
 for _, finding := range report.Findings {
  if finding.Code != "unexpected_entry" { t.Fatalf("finding: %+v", finding) }
 }
 if _, err := os.Lstat(filepath.Join(dir, "hidden-link")); err != nil { t.Fatalf("audit changed link: %v", err) }
 if data, err := os.ReadFile(filepath.Join(dir, "operator-note")); err != nil || string(data) != "leave intact" {
  t.Fatalf("audit modified unrelated file: %q %v", data, err)
 }
}

func TestAuditUnexpectedEntriesBeyondFindingLimit(t *testing.T) {
 dir := privateDir(t)
 for i:=0;i<maxFindings+2;i++ {
  if err:=os.Mkdir(filepath.Join(dir,"unexpected-"+itoaAuditTest(i)),0700);err!=nil {t.Fatal(err)}
 }
 report,err:=Audit(dir)
 if err==nil || !strings.Contains(err.Error(),"finding limit exceeded") {t.Fatalf("incomplete audit succeeded: %v",err)}
 if report.UnexpectedEntries!=maxFindings+2 || report.DroppedFindings!=2 || !report.Truncated {
  t.Fatalf("lost unexpected entry evidence: %+v",report)
 }
}
