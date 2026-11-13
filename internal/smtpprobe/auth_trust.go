package smtpprobe

import "strings"

// trustworthyAUTH rejects ambiguous AUTH advertisements as protocol evidence.
// A server may advertise AUTH once using the RFC 4954 form or the historical
// AUTH= form. Mixed, duplicate, empty, or malformed lines cannot establish a
// trustworthy set of mechanisms for a read-only diagnostic.
func trustworthyAUTH(lines []string) bool {
 count := 0
 if len(lines) < 2 { return false }
 for _, line := range lines[1:] {
  fields := strings.Fields(line)
  if len(fields) == 0 { continue }
  keyword := strings.ToUpper(fields[0])
  if keyword != "AUTH" && !strings.HasPrefix(keyword, "AUTH=") { continue }
  count++
  if count != 1 { return false }
  mechanisms := fields[1:]
  if keyword != "AUTH" {
   mechanisms = append([]string{keyword[len("AUTH="):]}, mechanisms...)
  }
  if len(mechanisms) == 0 { return false }
  seen := make(map[string]bool, len(mechanisms))
  for _, mechanism := range mechanisms {
   if !validAuthMechanism(mechanism) { return false }
   normalized := strings.ToUpper(mechanism)
   if seen[normalized] { return false }
   seen[normalized] = true
  }
 }
 return count == 1
}
