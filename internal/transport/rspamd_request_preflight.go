package transport

import (
 "fmt"
 "strings"
)

// rspamdValidateRequestPreflight refuses encodings the HTTP compatibility
// worker cannot decode. A non-zstd encoding must not silently reach the MIME
// scanner as though it were a plain RFC 5322 message.
func rspamdValidateRequestPreflight(m rspamdRequestMetadata) (string, error) {
 if m.Compression != "" {
  return "", fmt.Errorf("unsupported Compression header")
 }
 encoding := strings.TrimSpace(m.ContentEncoding)
 if encoding != "" && !strings.EqualFold(encoding, "identity") {
  return "", fmt.Errorf("unsupported Content-Encoding header")
 }
 if m.Helo == "" {
  return "", nil
 }
 helo, valid := parseSMTPXForwardHelo(m.Helo)
 if !valid {
  return "", fmt.Errorf("invalid Helo header")
 }
 return helo, nil
}
