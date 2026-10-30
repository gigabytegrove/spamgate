package transport

import (
 "errors"
 "net/mail"
 "strconv"
 "strings"
)

// SMTP path syntax is deliberately stricter than mail.ParseAddress: an
// RFC 5321 envelope requires angle brackets, and ESMTP parameters must be
// explicitly understood. Silently ignoring trailing parameters is unsafe.
func parseSMTPPath(line, prefix string, allowNull bool) (string, string, error) {
 if !strings.HasPrefix(strings.ToUpper(line), prefix) {
  return "", "", errors.New("invalid SMTP verb")
 }
 value := strings.TrimSpace(line[len(prefix):])
 if !strings.HasPrefix(value, "<") {
  return "", "", errors.New("SMTP path requires angle brackets")
 }
 end := strings.IndexByte(value, '>')
 if end < 0 { return "", "", errors.New("unterminated SMTP path") }
 address := value[1:end]
 suffix := value[end+1:]
 if suffix != "" && suffix[0] != ' ' && suffix[0] != '\t' {
  return "", "", errors.New("invalid SMTP path suffix")
 }
 if address == "" && !allowNull {
  return "", "", errors.New("empty recipient")
 }
 if len(address) > 254 || strings.ContainsAny(address, "<>\r\n\t ") {
  return "", "", errors.New("invalid SMTP address")
 }
 if address != "" {
  parsed, err := mail.ParseAddress(address)
  if err != nil || parsed.Address != address {
   return "", "", errors.New("invalid SMTP mailbox")
  }
 }
 return address, strings.TrimSpace(suffix), nil
}

func parseSMTPMail(line string) (string, int64, error) {
 address, params, err := parseSMTPPath(line, "MAIL FROM:", true)
 if err != nil { return "", 0, err }
 size := int64(-1)
 seenBody := false
 for _, param := range strings.Fields(params) {
  upper := strings.ToUpper(param)
  switch {
  case strings.HasPrefix(upper, "SIZE="):
   if size >= 0 { return "", 0, errors.New("duplicate SIZE") }
   digits := param[len("SIZE="):]
   if digits == "" { return "", 0, errors.New("empty SIZE") }
   for _, c := range digits {
    if c < '0' || c > '9' { return "", 0, errors.New("non-numeric SIZE") }
   }
   n, e := strconv.ParseInt(digits, 10, 64)
   if e != nil { return "", 0, errors.New("SIZE overflow") }
   size = n
  case upper == "BODY=7BIT" || upper == "BODY=8BITMIME":
   if seenBody { return "", 0, errors.New("duplicate BODY") }
   seenBody = true
  default:
   return "", 0, errors.New("unsupported ESMTP MAIL parameter")
  }
 }
 return address, size, nil
}

func parseSMTPRecipient(line string) (string, error) {
 address, params, err := parseSMTPPath(line, "RCPT TO:", false)
 if err != nil { return "", err }
 // DSN parameters are not advertised by the listener; never silently
 // discard NOTIFY/ORCPT or other recipient-specific delivery requests.
 if params != "" { return "", errors.New("unsupported RCPT parameter") }
 return address, nil
}
