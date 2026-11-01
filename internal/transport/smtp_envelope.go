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
 // The listener does not advertise SMTPUTF8. Accepting a UTF-8 mailbox
 // would acknowledge an envelope the next hop may be unable to relay.
 for _, c := range address {
  if c > 0x7f { return "", "", errors.New("SMTPUTF8 mailbox not advertised") }
 }
 if address != "" {
  parsed, err := mail.ParseAddress(address)
  if err != nil || parsed.Address != address {
   return "", "", errors.New("invalid SMTP mailbox")
  }
 }
 return address, strings.TrimSpace(suffix), nil
}

// smtpMailParameters preserves the MAIL transaction's ESMTP declarations.
// SIZE is a maximum, not merely a diagnostic hint; the default BODY is 7BIT.
type smtpMailParameters struct {
 DeclaredSize int64
 EightBit bool
}

var (
 errSMTPDeclaredSize = errors.New("SMTP DATA exceeds declared SIZE")
 errSMTPBody7Bit = errors.New("SMTP DATA contains 8-bit bytes without BODY=8BITMIME")
 errSMTPHeaderUTF8 = errors.New("SMTPUTF8 header fields not advertised")
)

func parseSMTPMailParameters(line string) (string, smtpMailParameters, error) {
 params := smtpMailParameters{DeclaredSize: -1}
 address, options, err := parseSMTPPath(line, "MAIL FROM:", true)
 if err != nil { return "", params, err }
 seenBody := false
 for _, option := range strings.Fields(options) {
  upper := strings.ToUpper(option)
  switch {
  case strings.HasPrefix(upper, "SIZE="):
   if params.DeclaredSize >= 0 { return "", params, errors.New("duplicate SIZE") }
   digits := option[len("SIZE="):]
   if digits == "" { return "", params, errors.New("empty SIZE") }
   for _, c := range digits {
    if c < '0' || c > '9' { return "", params, errors.New("non-numeric SIZE") }
   }
   n, e := strconv.ParseInt(digits, 10, 64)
   if e != nil { return "", params, errors.New("SIZE overflow") }
   params.DeclaredSize = n
  case upper == "BODY=7BIT" || upper == "BODY=8BITMIME":
   if seenBody { return "", params, errors.New("duplicate BODY") }
   seenBody = true
   params.EightBit = upper == "BODY=8BITMIME"
  default:
   return "", params, errors.New("unsupported ESMTP MAIL parameter")
  }
 }
 return address, params, nil
}

// Retain the original parser contract for existing callers and tests.
func parseSMTPMail(line string) (string, int64, error) {
 address, params, err := parseSMTPMailParameters(line)
 return address, params.DeclaredSize, err
}

func parseSMTPRecipient(line string) (string, error) {
 address, params, err := parseSMTPPath(line, "RCPT TO:", false)
 if err != nil { return "", err }
 // DSN parameters are not advertised by the listener; never silently
 // discard NOTIFY/ORCPT or other recipient-specific delivery requests.
 if params != "" { return "", errors.New("unsupported RCPT parameter") }
 return address, nil
}

// validateSMTPDataContract is deliberately called after dot unstuffing and
// before scan, quarantine, relay or durable queue publication. A rejected
// transaction never transfers delivery responsibility to SpamGate.
func validateSMTPDataContract(params smtpMailParameters, raw []byte) error {
 if params.DeclaredSize >= 0 && int64(len(raw)) > params.DeclaredSize { return errSMTPDeclaredSize }
 if !params.EightBit && containsEightBit(raw) { return errSMTPBody7Bit }
 // BODY=8BITMIME permits eight-bit body octets, not RFC 6532 UTF-8
 // header fields. This listener does not advertise SMTPUTF8.
 headerUTF8, headerErr := inspectRelayHeader(raw)
 if headerErr != nil || headerUTF8 { return errSMTPHeaderUTF8 }
 return nil
}
