package smtpprobe

import "testing"

// These findings are strictly observational. They do not attempt AUTH,
// submit credentials, or infer a mail-host policy from a failed TLS handshake.
func TestAssessTLSCapabilityTransitions(t *testing.T) {
 base := Result{
  EHLOCode: 250, StartTLSAdvertised: true,
  StartTLSVerified: true, PostTLSEHLOCode: 250,
 }
 cases := []struct {
  name string
  beforeSize, afterSize bool
  beforeAuth, afterAuth []string
  verified bool
  postCode int
  expected []string
  forbidden []string
 }{
  {"size disappears", true, false, nil, nil, true, 250,
   []string{"SIZE_NOT_ADVERTISED_AFTER_TLS"}, []string{"SIZE_ADVERTISED_ONLY_AFTER_TLS"}},
  {"size appears", false, true, nil, nil, true, 250,
   []string{"SIZE_ADVERTISED_ONLY_AFTER_TLS"}, []string{"SIZE_NOT_ADVERTISED_AFTER_TLS"}},
  {"size unchanged", true, true, nil, nil, true, 250,
   nil, []string{"SIZE_NOT_ADVERTISED_AFTER_TLS","SIZE_ADVERTISED_ONLY_AFTER_TLS"}},
  {"auth appears after TLS", false, false, nil, []string{"PLAIN"}, true, 250,
   []string{"AUTH_ADVERTISED_ONLY_AFTER_TLS"}, []string{"AUTH_NOT_ADVERTISED_AFTER_TLS"}},
  {"auth already available", false, false, []string{"PLAIN"}, []string{"PLAIN"}, true, 250,
   nil, []string{"AUTH_ADVERTISED_ONLY_AFTER_TLS","AUTH_NOT_ADVERTISED_AFTER_TLS"}},
  {"auth disappears", false, false, []string{"PLAIN"}, nil, true, 250,
   []string{"AUTH_NOT_ADVERTISED_AFTER_TLS"}, []string{"AUTH_ADVERTISED_ONLY_AFTER_TLS"}},
  {"no verified TLS", true, false, nil, []string{"PLAIN"}, false, 250,
   nil, []string{"SIZE_NOT_ADVERTISED_AFTER_TLS","AUTH_ADVERTISED_ONLY_AFTER_TLS"}},
  {"post TLS EHLO rejected", true, false, nil, []string{"PLAIN"}, true, 550,
   nil, []string{"SIZE_NOT_ADVERTISED_AFTER_TLS","AUTH_ADVERTISED_ONLY_AFTER_TLS"}},
  {"post TLS EHLO absent", true, false, nil, []string{"PLAIN"}, true, 0,
   nil, []string{"SIZE_NOT_ADVERTISED_AFTER_TLS","AUTH_ADVERTISED_ONLY_AFTER_TLS"}},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   r := base
   r.SizeAdvertised, r.PostTLSSizeAdvertised = tc.beforeSize, tc.afterSize
   r.AuthMechanisms, r.PostTLSAuthMechanisms = tc.beforeAuth, tc.afterAuth
   r.StartTLSVerified, r.PostTLSEHLOCode = tc.verified, tc.postCode
   codes := findingCodes(Assess(r))
   for _, code := range tc.expected {
    if !codes[code] { t.Errorf("missing %s in %+v", code, codes) }
   }
   for _, code := range tc.forbidden {
    if codes[code] { t.Errorf("unsupported %s in %+v", code, codes) }
   }
  })
 }
}
