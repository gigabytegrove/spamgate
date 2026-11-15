package transport

import (
 "errors"
 "fmt"
 "net/http"
 "strings"
 "unicode/utf8"
)

type rspamdRequestMetadata struct {
 Sender string
 Helo string
 ClientIP string
 Recipients []string
 Flags string
 Compression string
 ContentEncoding string
}

// Validate metadata before it becomes scanner identity or a persisted audit value.
// Header maps can contain non-canonical keys when constructed by middleware;
// Header.Values alone would miss them and allow ambiguous duplicate identities.
func rspamdValidHeaderValue(value string, max int) bool {
 if len(value) > max || !utf8.ValidString(value) { return false }
 for _, r := range value {
  if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) { return false }
 }
 return true
}

func rspamdSingleHeader(h http.Header, name string, max int) (string, error) {
 var value string
 count := 0
 for key, values := range h {
  if !strings.EqualFold(key, name) { continue }
  count += len(values)
  if count > 1 { return "", fmt.Errorf("duplicate %s header", name) }
  if len(values) == 1 { value = values[0] }
 }
 if !rspamdValidHeaderValue(value, max) {
  return "", fmt.Errorf("%s header contains invalid text or exceeds %d bytes", name, max)
 }
 return value, nil
}

func rspamdReadRequestMetadata(h http.Header) (rspamdRequestMetadata, error) {
 var m rspamdRequestMetadata
 var err error
 if m.Sender, err = rspamdSingleHeader(h, "From", 512); err != nil { return m, err }
 if m.Helo, err = rspamdSingleHeader(h, "Helo", 255); err != nil { return m, err }
 if m.ClientIP, err = rspamdSingleHeader(h, "IP", 64); err != nil { return m, err }
 if m.Flags, err = rspamdSingleHeader(h, "Flags", 256); err != nil { return m, err }
 if m.Compression, err = rspamdSingleHeader(h, "Compression", 64); err != nil { return m, err }
 if m.ContentEncoding, err = rspamdSingleHeader(h, "Content-Encoding", 64); err != nil { return m, err }
 deliverTo, err := rspamdSingleHeader(h, "Deliver-To", 512)
 if err != nil { return m, err }
 rcpts := h.Values("Rcpt")
 if len(rcpts) > 100 { return m, errors.New("too many Rcpt headers") }
 m.Recipients = make([]string, 0, len(rcpts)+1)
 for _, recipient := range rcpts {
  if len(recipient) == 0 || len(recipient) > 512 { return m, errors.New("invalid Rcpt header length") }
  if !rspamdValidHeaderValue(recipient, 512) { return m, errors.New("Rcpt header contains invalid text") }
  identity, err := rspamdMailboxIdentity(recipient, false)
  if err != nil { return m, fmt.Errorf("invalid Rcpt header: %w", err) }
  m.Recipients = append(m.Recipients, identity)
 }
 if deliverTo != "" {
  identity, err := rspamdMailboxIdentity(deliverTo, false)
  if err != nil { return m, fmt.Errorf("invalid Deliver-To header: %w", err) }
  if len(m.Recipients) >= 100 { return m, errors.New("too many recipients") }
  m.Recipients = append(m.Recipients, identity)
 }
 m.Sender, err = rspamdMailboxIdentity(m.Sender, true)
 if err != nil { return m, fmt.Errorf("invalid From header: %w", err) }
 return m, nil
}
