package transport

import (
 "errors"
 "strings"
 "unicode/utf8"
)

// rspamdValidateMailboxStructure rejects ambiguous or malformed identities.
// This intentionally does not canonicalize or reinterpret SMTPUTF8 addresses.
func rspamdValidateMailboxStructure(value string) error {
 if !utf8.ValidString(value) { return errors.New("invalid mailbox encoding") }
 separator := -1
 quoted, escaped := false, false
 for i := 0; i < len(value); i++ {
  c := value[i]
  if c < 32 || c == 127 { return errors.New("mailbox contains control character") }
  if escaped { escaped = false; continue }
  if quoted && c == '\\' { escaped = true; continue }
  if c == '"' { quoted = !quoted; continue }
  if c == '@' && !quoted {
   if separator >= 0 { return errors.New("multiple mailbox separators") }
   separator = i
  }
 }
 if quoted || escaped || separator <= 0 || separator >= len(value)-1 {
  return errors.New("invalid mailbox separator or quoted local part")
 }
 local, domain := value[:separator], value[separator+1:]
 if strings.ContainsAny(domain, " \t\"\\") { return errors.New("invalid domain whitespace or quoting") }
 if strings.HasPrefix(local, "\"") {
  if len(local) < 2 || local[len(local)-1] != '"' { return errors.New("invalid quoted local part") }
 } else if strings.ContainsAny(local, " \t\"\\") {
  return errors.New("invalid unquoted local part")
 }
 if strings.HasPrefix(domain, "[") {
  if len(domain) < 3 || domain[len(domain)-1] != ']' || strings.ContainsAny(domain[1:len(domain)-1], "[]") {
   return errors.New("invalid domain literal")
  }
  return nil
 }
 if len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
  return errors.New("invalid domain label structure")
 }
 for _, label := range strings.Split(domain, ".") {
  if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
   return errors.New("invalid domain label")
  }
  for i := 0; i < len(label); i++ {
   c := label[i]
   if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
    return errors.New("invalid domain character")
   }
  }
 }
 return nil
}
