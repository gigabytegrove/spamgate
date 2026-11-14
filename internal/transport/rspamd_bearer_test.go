package transport

import (
 "net/http"
 "net/http/httptest"
 "testing"
)

func TestRspamdBearerAuthorized(t *testing.T) {
 const secret = "a-strong-test-token"
 for _, tc := range []struct {name string; values []string; want bool}{
  {"valid", []string{"Bearer "+secret}, true},
  {"case insensitive scheme", []string{"bearer "+secret}, true},
  {"raw token denied", []string{secret}, false},
  {"basic denied", []string{"Basic "+secret}, false},
  {"missing denied", nil, false},
  {"empty denied", []string{""}, false},
  {"duplicate denied", []string{"Bearer "+secret, "Bearer "+secret}, false},
  {"comma combined denied", []string{"Bearer "+secret+", Bearer "+secret}, false},
  {"leading whitespace denied", []string{" Bearer "+secret}, false},
  {"trailing whitespace denied", []string{"Bearer "+secret+" "}, false},
  {"wrong token denied", []string{"Bearer wrong"}, false},
  {"embedded whitespace denied", []string{"Bearer a strong-test-token"}, false},
 } {
  t.Run(tc.name, func(t *testing.T) {
   if got := rspamdBearerAuthorized(tc.values, secret); got != tc.want {
    t.Fatalf("authorization=%q got=%v want=%v", tc.values, got, tc.want)
   }
  })
 }
 if rspamdBearerAuthorized([]string{"Bearer token"}, "") { t.Fatal("empty configured token authorized") }
}

func TestRspamdHTTPBearerBoundary(t *testing.T) {
 networks, err := parseTrustedCIDRs("192.0.2.0/24")
 if err != nil { t.Fatal(err) }
 worker := &RspamdWorker{Trusted: networks, Token: "a-strong-test-token"}
 for _, tc := range []struct {name string; auth []string; status int}{
  {"raw denied", []string{"a-strong-test-token"}, http.StatusUnauthorized},
  {"wrong scheme denied", []string{"Basic a-strong-test-token"}, http.StatusUnauthorized},
  {"duplicate denied", []string{"Bearer a-strong-test-token", "Bearer a-strong-test-token"}, http.StatusUnauthorized},
  {"valid accepted", []string{"Bearer a-strong-test-token"}, http.StatusOK},
 } {
  t.Run(tc.name, func(t *testing.T) {
   req := httptest.NewRequest(http.MethodGet, "/ping", nil)
   req.RemoteAddr = "192.0.2.55:53000"
   for _, value := range tc.auth { req.Header.Add("Authorization", value) }
   rec := httptest.NewRecorder()
   worker.Handler().ServeHTTP(rec, req)
   if rec.Code != tc.status { t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.status, rec.Body.String()) }
  })
 }
}
