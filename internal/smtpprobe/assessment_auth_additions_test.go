package smtpprobe

import "testing"

// Changes in either direction must be observable without attempting AUTH.
func TestAssessAuthMechanismAdditionsAfterVerifiedTLS(t *testing.T) {
 cases := []struct {
  name string
  before, after []string
  verified bool
  postCode int
  added, removed bool
 }{
  {"added", []string{"PLAIN"}, []string{"PLAIN","LOGIN"}, true,250,true,false},
  {"added case normalized", []string{" plain "}, []string{"PLAIN","login"}, true,250,true,false},
  {"both directions", []string{"PLAIN","CRAM-MD5"}, []string{"PLAIN","LOGIN"}, true,250,true,true},
  {"unchanged", []string{"PLAIN","LOGIN"}, []string{"login","plain"}, true,250,false,false},
  {"removed", []string{"PLAIN","LOGIN"}, []string{"PLAIN"}, true,250,false,true},
  {"all removed", []string{"PLAIN"}, nil, true,250,false,false},
  {"first advertisement after TLS", nil, []string{"PLAIN"}, true,250,false,false},
  {"unverified", []string{"PLAIN"}, []string{"PLAIN","LOGIN"}, false,250,false,false},
  {"post EHLO rejected", []string{"PLAIN"}, []string{"PLAIN","LOGIN"}, true,550,false,false},
  {"post EHLO missing", []string{"PLAIN"}, []string{"PLAIN","LOGIN"}, true,0,false,false},
  {"initial EHLO rejected", []string{"PLAIN"}, []string{"PLAIN","LOGIN"}, true,250,false,false},
 }
 for _,tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   initial := 250
   if tc.name=="initial EHLO rejected" { initial=550 }
   r:=Result{EHLOCode:initial,StartTLSAdvertised:true,StartTLSVerified:tc.verified,PostTLSEHLOCode:tc.postCode,AuthMechanisms:tc.before,PostTLSAuthMechanisms:tc.after}
   codes:=findingCodes(Assess(r))
   if codes["AUTH_MECHANISMS_ADDED_AFTER_TLS"]!=tc.added || codes["AUTH_MECHANISMS_CHANGED_AFTER_TLS"]!=tc.removed {
    t.Fatalf("findings=%+v expected added=%v removed=%v",Assess(r),tc.added,tc.removed)
   }
  })
 }
}
