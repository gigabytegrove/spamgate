package smtpprobe

import "testing"

// These are protocol observations only: no credentials, mail submission, or
// production host is involved in this assessment.
func TestAssessEHLOFailureEvidence(t *testing.T) {
 cases := []struct {
  name string
  result Result
  want string
 }{
  {"initial rejected", Result{EHLOCode: 550}, "EHLO_NOT_ACCEPTED"},
  {"initial timeout has no response evidence", Result{}, ""},
  {"post TLS rejected", Result{EHLOCode:250, StartTLSAdvertised:true, StartTLSVerified:true, PostTLSEHLOCode: 550}, "POST_TLS_EHLO_NOT_ACCEPTED"},
  {"unverified TLS does not infer post TLS result", Result{EHLOCode:250, StartTLSAdvertised:true, PostTLSEHLOCode:550}, ""},
  {"post TLS not attempted", Result{EHLOCode:250, StartTLSAdvertised:true, StartTLSVerified:true}, ""},
 }
 for _,tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   codes:=findingCodes(Assess(tc.result))
   if tc.want!="" && !codes[tc.want] {t.Fatalf("missing %s: %+v",tc.want,codes)}
   if tc.want=="" && (codes["EHLO_NOT_ACCEPTED"]||codes["POST_TLS_EHLO_NOT_ACCEPTED"]) {t.Fatalf("unsupported EHLO failure inference: %+v",codes)}
  })
 }
}

func TestAssessSIZEPolicyDriftRequiresVerifiedEvidence(t *testing.T) {
 base:=Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250,
  SizeAdvertised:true,SizeLimitKnown:true,SizeLimitBytes:100000,
  PostTLSSizeAdvertised:true,PostTLSSizeLimitKnown:true,PostTLSSizeLimitBytes:50000}
 cases:=[]struct{name string; mutate func(*Result); want bool}{
  {"decreased",func(*Result){},true},
  {"increased",func(r *Result){r.PostTLSSizeLimitBytes=200000},true},
  {"unchanged",func(r *Result){r.PostTLSSizeLimitBytes=r.SizeLimitBytes},false},
  {"unverified TLS",func(r *Result){r.StartTLSVerified=false},false},
  {"post TLS EHLO rejected",func(r *Result){r.PostTLSEHLOCode=550},false},
  {"unknown initial limit",func(r *Result){r.SizeLimitKnown=false},false},
  {"unknown post TLS limit",func(r *Result){r.PostTLSSizeLimitKnown=false},false},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   r:=base
   tc.mutate(&r)
   got:=findingCodes(Assess(r))["SIZE_LIMIT_CHANGED_AFTER_TLS"]
   if got!=tc.want {t.Fatalf("SIZE drift=%v want=%v",got,tc.want)}
  })
 }
}
