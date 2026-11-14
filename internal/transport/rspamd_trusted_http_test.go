package transport

import (
 "net/http"
 "net/http/httptest"
 "testing"
)

func TestRspamdHTTPTrustBoundaryBeforeAuthentication(t *testing.T) {
 networks, err := parseTrustedCIDRs("192.0.2.0/24,2001:db8::/64")
 if err != nil { t.Fatal(err) }
 worker := &RspamdWorker{Trusted: networks, Token: "test-secret"}
 cases := []struct {
  name string
  remote string
  want int
 }{
  {"IPv4 trusted reaches token check", "192.0.2.55:53000", http.StatusUnauthorized},
  {"IPv4 outside denied", "192.0.3.55:53000", http.StatusForbidden},
  {"IPv6 trusted reaches token check", "[2001:db8::55]:53000", http.StatusUnauthorized},
  {"IPv6 outside denied", "[2001:db9::55]:53000", http.StatusForbidden},
  {"malformed remote denied", "192.0.2.55", http.StatusForbidden},
  {"unparseable address denied", "not-an-ip:53000", http.StatusForbidden},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   req := httptest.NewRequest(http.MethodGet, "/ping", nil)
   req.RemoteAddr = tc.remote
   recorder := httptest.NewRecorder()
   worker.Handler().ServeHTTP(recorder, req)
   if recorder.Code != tc.want {
    t.Fatalf("remote=%q status=%d want=%d", tc.remote, recorder.Code, tc.want)
   }
  })
 }
}
