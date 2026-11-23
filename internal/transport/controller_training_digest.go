package transport

import (
 "crypto/sha256"
 "crypto/subtle"
 "encoding/base64"
 "net/http"
 "strings"
)

// validateControllerTrainingDigest verifies an optional RFC 9530 Content-Digest.
// Only sha-256 is supported; unsupported or ambiguous digests fail closed.
// The digest is checked on the exact received representation, before training.
func validateControllerTrainingDigest(r *http.Request, body []byte) int {
 if r == nil { return http.StatusBadRequest }
 values := controllerHeaderValues(r.Header, "Content-Digest")
 if len(values) == 0 { return http.StatusOK }
 if len(values) != 1 { return http.StatusBadRequest }
 value := strings.TrimSpace(values[0])
 if !strings.HasPrefix(value, "sha-256=:") || !strings.HasSuffix(value, ":") {
  return http.StatusBadRequest
 }
 encoded := strings.TrimSuffix(strings.TrimPrefix(value, "sha-256=:"), ":")
 if encoded == "" || strings.ContainsAny(encoded, " \t\r\n,;") { return http.StatusBadRequest }
 digest, err := base64.StdEncoding.Strict().DecodeString(encoded)
 if err != nil || len(digest) != sha256.Size { return http.StatusBadRequest }
 actual := sha256.Sum256(body)
 if subtle.ConstantTimeCompare(digest, actual[:]) != 1 { return http.StatusBadRequest }
 return http.StatusOK
}
