package transport

import (
 "net/netip"
 "strings"
)

// validSMTPGreetingIdentity validates the RFC 5321 EHLO/HELO argument before
// it is used as a scanner identity. SMTP address literals use square brackets;
// IPv6 literals require the explicit IPv6: prefix. No Unicode case folding,
// DNS resolution, or interpretation of whitespace is performed.
func validSMTPGreetingIdentity(value string) bool {
 if value == "" || len(value) > 255 || strings.TrimSpace(value) != value {
  return false
 }
 for i := 0; i < len(value); i++ {
  if value[i] < 33 || value[i] > 126 {
   return false
  }
 }
 if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
  if len(value) < 3 || value[0] != '[' || value[len(value)-1] != ']' {
   return false
  }
  literal := value[1:len(value)-1]
  if len(literal) >= 5 && strings.EqualFold(literal[:5], "IPv6:") {
   addr, err := netip.ParseAddr(literal[5:])
   return err == nil && addr.Is6() && addr.Zone() == ""
  }
  addr, err := netip.ParseAddr(literal)
  return err == nil && addr.Is4()
 }
 if len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
  return false
 }
 for _, label := range strings.Split(value, ".") {
  if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
   return false
  }
  for i := 0; i < len(label); i++ {
   c := label[i]
   if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
    return false
   }
  }
 }
 return true
}
