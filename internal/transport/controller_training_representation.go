package transport

import (
 "net/http"
 "mime"
 "strings"
)

// The controller consumes an RFC 5322 message, not a form or a compressed
// transfer. Refuse ambiguous encodings before feeding bytes to Bayes.
func validateControllerTrainingRepresentation(r *http.Request) int {
 if r == nil { return http.StatusBadRequest }
 if len(r.Header.Values("Content-Encoding")) > 0 {
  // Go does not decode request content encodings. Even "identity" is
  // rejected to prevent proxy/backend interpretation differences.
  return http.StatusUnsupportedMediaType
 }
 values := r.Header.Values("Content-Type")
 if len(values) == 0 { return http.StatusOK } // Rspamd-compatible raw uploads
 if len(values) != 1 { return http.StatusUnsupportedMediaType }
 value := strings.TrimSpace(values[0])
 if value == "" { return http.StatusUnsupportedMediaType }
 typ, params, err := mime.ParseMediaType(value)
 if err != nil || len(params) != 0 { return http.StatusUnsupportedMediaType }
 switch typ {
 case "message/rfc822", "application/octet-stream", "text/plain":
  return http.StatusOK
 default:
  return http.StatusUnsupportedMediaType
 }
}
