package main

import (
 "fmt"
 "sort"

 "github.com/gigabytegrove/spamgate/internal/spoolaudit"
)

// integrityGateFailures reports aggregate finding categories, not message
// contents or queue identifiers. FindingCounts is authoritative even when
// individual diagnostic findings have been truncated.
func integrityGateFailures(report spoolaudit.Report) []string {
 codes := make([]string, 0, len(report.FindingCounts))
 for code, count := range report.FindingCounts {
  if count > 0 { codes = append(codes, code) }
 }
 sort.Strings(codes)
 failures := make([]string, 0, len(codes)+1)
 for _, code := range codes {
  failures = append(failures, fmt.Sprintf("integrity:%s=%d", code, report.FindingCounts[code]))
 }
 if report.Truncated {
  failures = append(failures, "integrity:findings_truncated")
 }
 // Fail closed if a caller constructs an inconsistent report.
 if report.HasFindings() && len(failures) == 0 {
  failures = append(failures, "integrity:unclassified_findings")
 }
 return failures
}
