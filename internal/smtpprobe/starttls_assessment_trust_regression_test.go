package smtpprobe

import "testing"

func TestStartTLSAssessmentEvidenceBoundaries(t *testing.T) {
 cases := []struct {
  name string
  warnings []string
  untrustworthy bool
 }{
  {"valid",nil,false},
  {"malformed",[]string{"MALFORMED_STARTTLS_ADVERTISEMENT"},true},
  {"duplicate",[]string{"DUPLICATE_STARTTLS_EXTENSION"},true},
  {"unrelated",[]string{"DUPLICATE_AUTH_EXTENSION"},false},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   if got:=untrustworthySTARTTLS(tc.warnings);got!=tc.untrustworthy {t.Fatalf("trust=%v want=%v",got,tc.untrustworthy)}
   pre:=Assess(Result{BannerCode:220,EHLOCode:250,StartTLSAdvertised:true,StartTLSReplyCode:454,EHLOWarnings:tc.warnings})
   if got:=findingPresent(pre,"STARTTLS_COMMAND_REJECTED");got==tc.untrustworthy {
    t.Fatalf("unjustified pre-TLS command verdict: %+v",pre)
   }
   post:=Assess(Result{BannerCode:220,EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250,PostTLSStartTLSAdvertised:true,PostTLSEHLOWarnings:tc.warnings})
   if got:=findingPresent(post,"POST_TLS_STARTTLS_EVIDENCE_UNTRUSTWORTHY");got!=tc.untrustworthy {
    t.Fatalf("post-TLS ambiguity finding mismatch: %+v",post)
   }
   if got:=findingPresent(post,"STARTTLS_ADVERTISED_AFTER_TLS");got==tc.untrustworthy {
    t.Fatalf("unjustified post-TLS advertisement verdict: %+v",post)
   }
  })
 }
}
