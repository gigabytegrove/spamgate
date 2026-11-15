package transport

import (
 "crypto/subtle"
 "net/http"
 "strings"
)

// rspamdBearerAuthorized accepts exactly one RFC 6750 Bearer credential.
// The token is never accepted without the authentication scheme.
func rspamdBearerAuthorized(headers []string, expected string) bool {
 if expected == "" || len(headers) != 1 { return false }
 value := headers[0]
 if len(value) < 8 || !strings.EqualFold(value[:7], "Bearer ") { return false }
 supplied := value[7:]
 if supplied == "" || strings.TrimSpace(supplied) != supplied || strings.ContainsAny(supplied, " \t\r\n,") { return false }
 return subtle.ConstantTimeCompare([]byte(supplied), []byte(expected)) == 1
}

// rspamdAuthorizationValues enumerates all case-insensitive Authorization keys.
// Middleware can construct a noncanonical http.Header map directly; Header.Values
// only finds the canonical map entry and must not be used for this trust boundary.
func rspamdAuthorizationValues(h http.Header) []string {
 var values []string
 for key, entries := range h {
  if !strings.EqualFold(key, "Authorization") { continue }
  values = append(values, entries...)
  if len(values) > 1 { return values }
 }
 return values
}
