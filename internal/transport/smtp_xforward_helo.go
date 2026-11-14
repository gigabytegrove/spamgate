package transport

import (
 "net/netip"
 "strings"
)

// parseSMTPXForwardHelo validates the original SMTP greeting supplied by a
// trusted Postfix XFORWARD peer. Never allow an arbitrary wire token to be
// forwarded into SPF HELO evaluation or retained message metadata.
func parseSMTPXForwardHelo(value string) (string, bool) {
 if value == "[UNAVAILABLE]" || value == "[TEMPUNAVAIL]" {
  return "", true
 }
 if len(value) == 0 || len(value) > 255 || strings.TrimSpace(value) != value {
  return "", false
 }
 for i := 0; i < len(value); i++ {
  if value[i] <= 0x20 || value[i] >= 0x7f {
   return "", false
  }
 }
 if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
  if len(value) < 3 || value[0] != '[' || value[len(value)-1] != ']' {
   return "", false
  }
  candidate := value[1:len(value)-1]
  if strings.HasPrefix(candidate, "IPv6:") {
   candidate = strings.TrimPrefix(candidate, "IPv6:")
   addr, err := netip.ParseAddr(candidate)
   if err != nil || !addr.Is6() || addr.Is4In6() || addr.Zone() != "" || strings.Contains(candidate, ".") {
   return "", false
  }
  return value, true
  }
  addr, err := netip.ParseAddr(candidate)
  if err != nil || !addr.Is4() {
   return "", false
  }
  return value, true
 }
 // HELO DNS names are ASCII LDH labels; do not silently normalize a
 // malformed value into a different SPF identity.
 if len(value) > 253 {
  return "", false
 }
 for _, label := range strings.Split(value, ".") {
  if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
   return "", false
  }
  for i := 0; i < len(label); i++ {
   c := label[i]
   if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (c == '-' && i > 0 && i < len(label)-1)) {
    return "", false
   }
  }
 }
 return value, true
}
