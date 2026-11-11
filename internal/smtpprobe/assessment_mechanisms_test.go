package smtpprobe

import "testing"

func TestMechanismSetNormalizesAndDeduplicates(t *testing.T) {
 got := mechanismSet([]string{"plain", " PLAIN ", "login", "", "  "})
 if len(got) != 2 || !got["PLAIN"] || !got["LOGIN"] {
  t.Fatalf("unexpected normalized mechanisms: %#v", got)
 }
}

func TestAssessMechanismChangesAfterVerifiedTLS(t *testing.T) {
 cases := []struct {
  name string
  result Result
  changed bool
  missing bool
 }{
  {"one removed",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250,AuthMechanisms:[]string{"PLAIN","LOGIN"},PostTLSAuthMechanisms:[]string{"plain"}},true,false},
  {"case insensitive",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250,AuthMechanisms:[]string{"PLAIN"},PostTLSAuthMechanisms:[]string{"plain","LOGIN"}},false,false},
  {"all removed",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250,AuthMechanisms:[]string{"PLAIN"}},false,true},
  {"failed EHLO",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:550,AuthMechanisms:[]string{"PLAIN"},PostTLSAuthMechanisms:[]string{"LOGIN"}},false,false},
  {"unverified TLS",Result{EHLOCode:250,StartTLSAdvertised:true,PostTLSEHLOCode:250,AuthMechanisms:[]string{"PLAIN"},PostTLSAuthMechanisms:[]string{"LOGIN"}},false,false},
  {"no initial AUTH",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250,PostTLSAuthMechanisms:[]string{"PLAIN"}},false,false},
 }
 for _,tc := range cases {
  t.Run(tc.name,func(t *testing.T) {
   codes := findingCodes(Assess(tc.result))
   if codes["AUTH_MECHANISMS_CHANGED_AFTER_TLS"] != tc.changed ||
    codes["AUTH_NOT_ADVERTISED_AFTER_TLS"] != tc.missing {
    t.Fatalf("findings=%#v, want changed=%v missing=%v",codes,tc.changed,tc.missing)
   }
  })
 }
}
