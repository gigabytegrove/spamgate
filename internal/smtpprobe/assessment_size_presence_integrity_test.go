package smtpprobe

import "testing"

// A malformed or contradictory SIZE extension is not proof that the
// extension appeared or disappeared across STARTTLS.
func TestAssessSizePresenceTransitionsRequireTrustworthyEvidence(t *testing.T) {
 cases := []struct {
  name string
  before, after bool
  beforeWarning, afterWarning string
  expected string
 }{
  {"disappeared", true, false, "", "", "SIZE_NOT_ADVERTISED_AFTER_TLS"},
  {"appeared", false, true, "", "", "SIZE_ADVERTISED_ONLY_AFTER_TLS"},
  {"ambiguous initial disappearance", true, false, "duplicate SIZE", "", ""},
  {"ambiguous post TLS appearance", false, true, "", "invalid SIZE", ""},
  {"ambiguous initial appearance", false, true, "invalid SIZE", "", ""},
  {"ambiguous post TLS disappearance", true, false, "", "duplicate SIZE", ""},
  {"both ambiguous", true, false, "invalid SIZE", "invalid SIZE", ""},
  {"neither advertised", false, false, "", "", ""},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   r := Result{EHLOCode:250, StartTLSAdvertised:true, StartTLSVerified:true, PostTLSEHLOCode:250,
    SizeAdvertised:tc.before, PostTLSSizeAdvertised:tc.after,
    SizeWarning:tc.beforeWarning, PostTLSSizeWarning:tc.afterWarning}
   codes:=findingCodes(Assess(r))
   for _, code := range []string{"SIZE_NOT_ADVERTISED_AFTER_TLS","SIZE_ADVERTISED_ONLY_AFTER_TLS"} {
    if codes[code] != (code==tc.expected) {
     t.Fatalf("%s: unexpected SIZE presence finding %s: %+v",tc.name,code,Assess(r))
    }
   }
  })
 }
}

func TestAssessSizePresenceTransitionsRequireVerifiedTLS(t *testing.T) {
 for _, tc := range []struct{name string; verified bool; postCode int}{
  {"TLS unverified",false,250},
  {"post TLS EHLO rejected",true,550},
  {"post TLS EHLO absent",true,0},
 } {
  t.Run(tc.name,func(t *testing.T){
   r:=Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:tc.verified,
    PostTLSEHLOCode:tc.postCode,SizeAdvertised:true}
   codes:=findingCodes(Assess(r))
   if codes["SIZE_NOT_ADVERTISED_AFTER_TLS"] || codes["SIZE_ADVERTISED_ONLY_AFTER_TLS"] {
    t.Fatalf("unsupported SIZE transition: %+v",Assess(r))
   }
  })
 }
}
