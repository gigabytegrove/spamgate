package transport

import (
 "errors"
 "strings"
)

// Remove only a complete SMTP path wrapper. Broad trimming silently converts
// malformed nested wrappers into seemingly valid identities.
func rspamdMailboxIdentity(value string, allowNull bool) (string, error) {
 value = strings.TrimSpace(value)
 if value == "" {
  if allowNull { return "", nil }
  return "", errors.New("empty recipient identity")
 }
 if value == "<>" && allowNull { return "", nil }
 if strings.HasPrefix(value, "<") || strings.HasSuffix(value, ">") {
  if len(value) < 3 || value[0] != '<' || value[len(value)-1] != '>' {
   return "", errors.New("malformed SMTP path wrapper")
  }
  value = value[1:len(value)-1]
 }
 if value == "" || strings.ContainsAny(value, "<>\r\n\x00,") {
  return "", errors.New("malformed mailbox identity")
 }
 if strings.TrimSpace(value) != value { return "", errors.New("whitespace inside SMTP path wrapper") }
 return value, nil
}
