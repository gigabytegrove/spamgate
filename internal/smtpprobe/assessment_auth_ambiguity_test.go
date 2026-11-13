package smtpprobe

import "testing"

// Invalid EHLO evidence must not be misreported as an authentication policy
// change. These tests do not authenticate or submit mail.
func TestAssessAmbiguousAUTHDoesNotInventDrift(t *testing.T) {
 base := Result{
  EHLOCode:250, StartTLSAdvertised:true, StartTLSVerified:true,
  PostTLSEHLOCode:250, AuthMechanisms:[]string{"PLAIN"},
  PostTLSAuthMechanisms:[]string{"LOGIN"},
 }
 cases := []struct{
  name string
  mutate func(*Result)
  warning string
  drift bool
 }{
  {"valid comparison",func(*Result){},"",true},
  {"invalid initial duplicate",func(r *Result){r.EHLOWarnings=[]string{"DUPLICATE_AUTH_MECHANISM"}},"AUTH_EVIDENCE_UNTRUSTWORTHY",false},
  {"invalid post TLS duplicate",func(r *Result){r.PostTLSEHLOWarnings=[]string{"DUPLICATE_AUTH_MECHANISM"}},"POST_TLS_AUTH_EVIDENCE_UNTRUSTWORTHY",false},
  {"invalid post TLS empty",func(r *Result){r.PostTLSEHLOWarnings=[]string{"EMPTY_AUTH_ADVERTISEMENT"};r.PostTLSAuthMechanisms=nil},"POST_TLS_AUTH_EVIDENCE_UNTRUSTWORTHY",false},
  {"invalid initial malformed",func(r *Result){r.EHLOWarnings=[]string{"MALFORMED_AUTH_MECHANISM"}},"AUTH_EVIDENCE_UNTRUSTWORTHY",false},
  {"invalid initial repeated extension",func(r *Result){r.EHLOWarnings=[]string{"DUPLICATE_EXTENSION"}},"AUTH_EVIDENCE_UNTRUSTWORTHY",false},
  {"invalid post TLS repeated extension",func(r *Result){r.PostTLSEHLOWarnings=[]string{"DUPLICATE_EXTENSION"}},"POST_TLS_AUTH_EVIDENCE_UNTRUSTWORTHY",false},
  {"unrelated warning",func(r *Result){r.PostTLSEHLOWarnings=[]string{"BINARYMIME_WITHOUT_CHUNKING"}},"",true},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   r:=base
   tc.mutate(&r)
   codes:=findingCodes(Assess(r))
   if tc.warning!="" && !codes[tc.warning] {t.Fatalf("missing %s: %+v",tc.warning,codes)}
   drift:=codes["AUTH_MECHANISMS_CHANGED_AFTER_TLS"] || codes["AUTH_MECHANISMS_ADDED_AFTER_TLS"] || codes["AUTH_NOT_ADVERTISED_AFTER_TLS"] || codes["AUTH_ADVERTISED_ONLY_AFTER_TLS"]
   if drift!=tc.drift {t.Fatalf("AUTH drift=%v want=%v: %+v",drift,tc.drift,codes)}
  })
 }
}

func TestAssessInvalidPostTLSAUTHNeverImpliesDisappearance(t *testing.T) {
 r:=Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250,
  AuthMechanisms:[]string{"PLAIN"},PostTLSEHLOWarnings:[]string{"DUPLICATE_AUTH_MECHANISM"}}
 codes:=findingCodes(Assess(r))
 if codes["AUTH_NOT_ADVERTISED_AFTER_TLS"] {t.Fatal("malformed AUTH misreported as disappearance")}
 if !codes["POST_TLS_AUTH_EVIDENCE_UNTRUSTWORTHY"] {t.Fatal("missing evidence warning")}
}
