package transport

import (
 "net/http"
 "net/http/httptest"
 "testing"
)

func TestRspamdAuthorizationCasefoldValues(t *testing.T) {
 const secret = "strong-test-token"
 cases := []struct {
  name string
  headers http.Header
  authorized bool
 }{
  {"canonical", http.Header{"Authorization": {"Bearer " + secret}}, true},
  {"lowercase only", http.Header{"authorization": {"Bearer " + secret}}, true},
  {"uppercase only", http.Header{"AUTHORIZATION": {"Bearer " + secret}}, true},
  {"canonical plus lowercase", http.Header{"Authorization": {"Bearer " + secret}, "authorization": {"Bearer " + secret}}, false},
  {"lowercase plus uppercase", http.Header{"authorization": {"Bearer " + secret}, "AUTHORIZATION": {"Bearer " + secret}}, false},
  {"valid plus invalid", http.Header{"Authorization": {"Bearer " + secret}, "authorization": {"Bearer wrong"}}, false},
  {"invalid plus valid", http.Header{"authorization": {"Bearer wrong"}, "AUTHORIZATION": {"Bearer " + secret}}, false},
  {"empty alias plus valid", http.Header{"Authorization": {"Bearer " + secret}, "authorization": {""}}, false},
  {"zero-value alias plus valid", http.Header{"Authorization": {"Bearer " + secret}, "authorization": {}}, true},
  {"missing", http.Header{}, false},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   got := rspamdBearerAuthorized(rspamdAuthorizationValues(tc.headers), secret)
   if got != tc.authorized { t.Fatalf("authorized=%v want=%v", got, tc.authorized) }
  })
 }
}

func TestRspamdHTTPRejectsAuthorizationAliases(t *testing.T) {
 networks, err := parseTrustedCIDRs("192.0.2.0/24")
 if err != nil { t.Fatal(err) }
 worker := &RspamdWorker{Trusted: networks, Token: "strong-test-token"}
 cases := []struct {
  name string
  headers http.Header
  status int
 }{
  {"canonical valid", http.Header{"Authorization": {"Bearer strong-test-token"}}, http.StatusOK},
  {"noncanonical valid", http.Header{"authorization": {"Bearer strong-test-token"}}, http.StatusOK},
  {"duplicate aliases", http.Header{"Authorization": {"Bearer strong-test-token"}, "authorization": {"Bearer strong-test-token"}}, http.StatusUnauthorized},
  {"invalid noncanonical", http.Header{"authorization": {"Bearer wrong"}}, http.StatusUnauthorized},
  {"valid and invalid aliases", http.Header{"Authorization": {"Bearer strong-test-token"}, "authorization": {"Bearer wrong"}}, http.StatusUnauthorized},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   req := httptest.NewRequest(http.MethodGet, "/ping", nil)
   req.RemoteAddr = "192.0.2.55:53000"
   req.Header = tc.headers
   rec := httptest.NewRecorder()
   worker.Handler().ServeHTTP(rec, req)
   if rec.Code != tc.status { t.Fatalf("status=%d want=%d body=%q", rec.Code, tc.status, rec.Body.String()) }
  })
 }
}
