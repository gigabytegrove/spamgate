package smtpprobe

import "testing"

func findingPresent(findings []Finding, code string) bool {
 for _, f := range findings {
  if f.Code == code { return true }
 }
 return false
}

func TestSMTPAssessmentEvidenceBoundaries(t *testing.T) {
 cases := []struct {
  name string
  result Result
  present []string
  absent []string
 }{
  {
   name:"rejected greeting cannot establish EHLO policy",
   result:Result{BannerCode:554, EHLOCode:250, AuthMechanisms:[]string{"PLAIN"}},
   present:[]string{"SMTP_GREETING_NOT_ACCEPTED"},
   absent:[]string{"AUTH_ADVERTISED_BEFORE_TLS","CLEARTEXT_CREDENTIAL_AUTH_ADVERTISED","STARTTLS_NOT_ADVERTISED"},
  },
  {
   name:"ambiguous AUTH does not establish advertised mechanisms",
   result:Result{BannerCode:220,EHLOCode:250,AuthMechanisms:[]string{"PLAIN"},EHLOWarnings:[]string{"DUPLICATE_AUTH_EXTENSION"}},
   present:[]string{"AUTH_EVIDENCE_UNTRUSTWORTHY"},
   absent:[]string{"AUTH_ADVERTISED_BEFORE_TLS","CLEARTEXT_CREDENTIAL_AUTH_ADVERTISED"},
  },
  {
   name:"trusted mixed case credential mechanism",
   result:Result{BannerCode:220,EHLOCode:250,AuthMechanisms:[]string{" plain "}},
   present:[]string{"AUTH_ADVERTISED_BEFORE_TLS","CLEARTEXT_CREDENTIAL_AUTH_ADVERTISED"},
  },
  {
   name:"trusted non credential mechanism",
   result:Result{BannerCode:220,EHLOCode:250,AuthMechanisms:[]string{"SCRAM-SHA-256"}},
   present:[]string{"AUTH_ADVERTISED_BEFORE_TLS"},
   absent:[]string{"CLEARTEXT_CREDENTIAL_AUTH_ADVERTISED"},
  },
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   got:=Assess(tc.result)
   for _, code:=range tc.present { if !findingPresent(got,code) {t.Errorf("missing %s: %+v",code,got)} }
   for _, code:=range tc.absent { if findingPresent(got,code) {t.Errorf("unexpected %s: %+v",code,got)} }
  })
 }
}
