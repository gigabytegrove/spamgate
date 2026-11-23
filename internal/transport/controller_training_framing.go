package transport

import (
 "net/http"
 "strconv"
 "strings"
)

// validateControllerTrainingFraming refuses ambiguous body lengths and
// transfer codings before a classifier sees any data. net/http normally
// normalizes these on the wire, but Handler is also used by direct callers.
func validateControllerTrainingFraming(r *http.Request) int {
 if r == nil || r.Body == nil { return http.StatusBadRequest }
 if r.ContentLength < -1 { return http.StatusBadRequest }
 lengths := controllerHeaderValues(r.Header, "Content-Length")
 if len(lengths) > 1 { return http.StatusBadRequest }
 if len(lengths) == 1 {
  value := lengths[0]
  if value == "" || strings.TrimSpace(value) != value { return http.StatusBadRequest }
  for _, ch := range value {
   if ch < '0' || ch > '9' { return http.StatusBadRequest }
  }
  n, err := strconv.ParseInt(value, 10, 64)
  if err != nil { return http.StatusBadRequest }
  if n > controllerMaxTrainingSampleBytes { return http.StatusRequestEntityTooLarge }
  if r.ContentLength != n { return http.StatusBadRequest }
 }
 // The controller accepts raw HTTP request bodies, not encoded chunks
 // presented directly by internal callers. The server decodes chunked
 // transfer framing before dispatching the handler.
 if len(r.TransferEncoding) > 0 {
  if len(r.TransferEncoding) != 1 || !strings.EqualFold(r.TransferEncoding[0], "chunked") {
   return http.StatusBadRequest
  }
  if r.ContentLength != -1 || len(lengths) != 0 { return http.StatusBadRequest }
 }
 if len(lengths) == 0 && r.ContentLength > controllerMaxTrainingSampleBytes {
  return http.StatusRequestEntityTooLarge
 }
 return http.StatusOK
}
