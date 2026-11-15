package transport

import (
 "errors"
 "net"
 "strings"
 "unicode"
 "unicode/utf8"
)

// rspamdValidateMailboxStructure checks an SMTP mailbox without normalizing
// the identity. It deliberately does not implement route-address syntax.
func rspamdValidateMailboxStructure(value string) error {
 if !utf8.ValidString(value) { return errors.New("invalid mailbox encoding") }
 if len(value) == 0 || len(value) > 320 { return errors.New("invalid mailbox length") }
 for _, r := range value {
  // SMTPUTF8 does not permit Unicode separators, format controls, or
  // bidirectional overrides in an envelope mailbox identity.
  if unicode.IsControl(r) || unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
   // ASCII space is legal only within a quoted local part, checked below.
   if r != ' ' { return errors.New("mailbox contains control or separator") }
  }
 }
 separator := -1
 quoted, escaped := false, false
 for i := 0; i < len(value); i++ {
  c := value[i]
  if escaped { escaped = false; continue }
  if quoted && c == '\\' { escaped = true; continue }
  if c == '"' { quoted = !quoted; continue }
  if c == '@' && !quoted {
   if separator >= 0 { return errors.New("multiple mailbox separators") }
   separator = i
  }
 }
 if quoted || escaped || separator <= 0 || separator >= len(value)-1 { return errors.New("invalid mailbox separator or quoted local part") }
 local, domain := value[:separator], value[separator+1:]
 if len(local) > 64 { return errors.New("local part exceeds 64 bytes") }
 if strings.HasPrefix(local, "\"") {
  if len(local) < 2 || local[len(local)-1] != '"' { return errors.New("invalid quoted local part") }
  for i := 1; i < len(local)-1; i++ {
   if local[i] == '\\' {
    i++
    if i >= len(local)-1 { return errors.New("invalid quoted escape") }
   } else if local[i] == '"' { return errors.New("unescaped quote in local part") }
  }
 } else {
  if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") { return errors.New("invalid local dot placement") }
  const asciiAtext = "!#$%&'*+-/=?^_`{|}~"
  for _, r := range local {
   if r == '.' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r < 128 && strings.ContainsRune(asciiAtext, r) { continue }
   if r >= 128 && !unicode.IsControl(r) && !unicode.IsSpace(r) && !unicode.Is(unicode.Cf, r) && !unicode.Is(unicode.Zl, r) && !unicode.Is(unicode.Zp, r) { continue }
   return errors.New("invalid unquoted local part")
  }
 }
 if strings.HasPrefix(domain, "[") {
  if len(domain) < 3 || !strings.HasSuffix(domain, "]") { return errors.New("invalid address literal") }
  literal := domain[1:len(domain)-1]
  if strings.HasPrefix(strings.ToLower(literal), "ipv6:") {
   literal = literal[5:]
   if net.ParseIP(literal) == nil || !strings.Contains(literal, ":") { return errors.New("invalid IPv6 address literal") }
   return nil
  }
  ip := net.ParseIP(literal)
  if ip == nil || ip.To4() == nil { return errors.New("invalid IPv4 address literal") }
  return nil
 }
 if len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") { return errors.New("invalid domain label structure") }
 for _, label := range strings.Split(domain, ".") {
  if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' { return errors.New("invalid domain label") }
  for i := 0; i < len(label); i++ {
   c := label[i]
   if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') { return errors.New("invalid domain character") }
  }
 }
 return nil
}
