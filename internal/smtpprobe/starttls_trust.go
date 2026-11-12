package smtpprobe

import "strings"

// trustworthyStartTLS requires exactly one syntactically valid STARTTLS
// extension. A duplicate or parameterized advertisement is ambiguous and must
// never authorize a TLS upgrade, even if another STARTTLS line is valid.
func trustworthyStartTLS(lines []string) bool {
 count := 0
 for _, line := range lines[1:] {
  fields := strings.Fields(line)
  if len(fields) == 0 { continue }
  if !strings.EqualFold(fields[0], "STARTTLS") { continue }
  count++
  if len(fields) != 1 { return false }
 }
 return count == 1
}
