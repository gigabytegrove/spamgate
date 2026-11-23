package transport

import (
 "crypto/subtle"
 "net"
 "net/http"
 "strconv"
)

// controllerAuthorize only trusts the socket peer, never proxy-supplied
// identity headers. An invalid or synthetic peer address fails closed.
func (s *RspamdController) controllerAuthorize(r *http.Request) int {
 if s == nil || s.Store == nil || !validControllerToken(s.Token) || len(s.Token) < 24 {
  return http.StatusServiceUnavailable
 }
 if r == nil {
  return http.StatusForbidden
 }
 host, port, err := net.SplitHostPort(r.RemoteAddr)
 if err != nil { return http.StatusForbidden }
 peer := net.ParseIP(host)
 if peer == nil { return http.StatusForbidden }
 number, err := strconv.Atoi(port)
 if err != nil || number < 1 || number > 65535 { return http.StatusForbidden }
 allowed := false
 for _, cidr := range s.Trusted {
  if cidr != nil && cidr.Contains(peer) { allowed = true; break }
 }
 if !allowed { return http.StatusForbidden }
 provided, valid := controllerCredential(r.Header)
 if !valid || subtle.ConstantTimeCompare([]byte(provided), []byte(s.Token)) != 1 {
  return http.StatusUnauthorized
 }
 if !s.Store.Config().SetupComplete { return http.StatusServiceUnavailable }
 return http.StatusOK
}
