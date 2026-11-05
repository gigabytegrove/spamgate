package spoolaudit

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

// A truncated audit cannot certify that accepted mail is durable: the
// unvisited tail may contain pending, corrupt or conflicting queue entries.
func TestAuditEntryLimitIsAnErrorAndPreservesQueue(t *testing.T) {
 dir := privateDir(t)
 for i := 0; i <= maxEntries; i++ {
  name := filepath.Join(dir, "unrelated-"+strconvForTest(i))
  if err := os.WriteFile(name, nil, 0600); err != nil { t.Fatal(err) }
 }
 report, err := Audit(dir)
 if err == nil || !strings.Contains(err.Error(), "entry limit exceeded") {
  t.Fatalf("truncated queue scan reported success: %+v, %v", report, err)
 }
 if !report.Truncated || !report.HasFindings() || !hasCode(report,"entry_limit") {
  t.Fatalf("missing incomplete-scan evidence: %+v", report)
 }
 entries, err := os.ReadDir(dir)
 if err != nil { t.Fatal(err) }
 if len(entries) != maxEntries+1 {
  t.Fatalf("read-only audit modified queue: got %d entries", len(entries))
 }
}

func strconvForTest(n int) string {
 if n == 0 { return "0" }
 var digits [20]byte
 i := len(digits)
 for n > 0 {
  i--
  digits[i] = byte('0'+n%10)
  n /= 10
 }
 return string(digits[i:])
}
