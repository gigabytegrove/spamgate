package transport

import "strings"

// validSMTPRecipientDomain accepts explicit ASCII DNS hostnames only.
// Recipient routing policy must never accept wildcard, address-literal,
// empty-label, or Unicode lookalike domains. Operators must configure IDNs
// using their canonical A-label (punycode) form.
func validSMTPRecipientDomain(domain string) bool {
 if len(domain) < 3 || len(domain) > 253 || !strings.Contains(domain, ".") {
  return false
 }
 for _, label := range strings.Split(domain, ".") {
  if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
   return false
  }
  for i := 0; i < len(label); i++ {
   c := label[i]
   if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
    continue
   }
   return false
  }
 }
 return true
}
