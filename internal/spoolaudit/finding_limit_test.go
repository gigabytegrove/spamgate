package spoolaudit

import (
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "testing"
)

// Every invalid published filename contributes a finding without needing
// malformed message contents. The auditor must not report success after
// suppressing the remainder of the findings.
func TestAuditFindingLimitFailsClosedWithoutQueueMutation(t *testing.T) {
 dir := privateDir(t)
 const total = maxFindings + 3
 for i := 0; i < total; i++ {
  name := filepath.Join(dir, "invalid-"+strconv.Itoa(i)+".json")
  if err := os.WriteFile(name, []byte("{}"), 0600); err != nil { t.Fatal(err) }
 }
 report, err := Audit(dir)
 if err == nil || !strings.Contains(err.Error(), "finding limit exceeded") {
  t.Fatalf("incomplete audit incorrectly succeeded: report=%+v err=%v", report, err)
 }
 if !report.Truncated || !report.HasFindings() {
  t.Fatalf("missing truncation evidence: %+v", report)
 }
 if report.Examined != total || report.Published != total {
  t.Fatalf("incorrect scan counters: %+v", report)
 }
 if len(report.Findings) != maxFindings {
  t.Fatalf("expected bounded findings %d, got %d", maxFindings, len(report.Findings))
 }
 entries, err := os.ReadDir(dir)
 if err != nil { t.Fatal(err) }
 if len(entries) != total {
  t.Fatalf("audit modified queue: expected %d entries, got %d", total, len(entries))
 }
}

func TestAuditFindingLimitBoundaryStillReturnsCompleteReport(t *testing.T) {
 dir := privateDir(t)
 for i := 0; i < maxFindings; i++ {
  name := filepath.Join(dir, "invalid-"+strconv.Itoa(i)+".json")
  if err := os.WriteFile(name, []byte("{}"), 0600); err != nil { t.Fatal(err) }
 }
 report, err := Audit(dir)
 if err != nil { t.Fatalf("complete bounded audit failed: %v", err) }
 if report.Truncated || len(report.Findings) != maxFindings {
  t.Fatalf("boundary audit incorrectly marked incomplete: %+v", report)
 }
}
