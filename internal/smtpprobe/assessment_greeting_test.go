package smtpprobe

import "testing"

func TestAssessSMTPGreetingFailures(t *testing.T) {
 cases := []struct {
  name string
  banner int
  ehlo int
  want bool
 }{
  {"temporary shutdown",421,0,true},
  {"permanent refusal",554,0,true},
  {"unexpected success",250,0,true},
  {"valid greeting",220,250,false},
  {"no greeting received",0,0,false},
  {"greeting rejected despite EHLO evidence",421,250,true},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T) {
   findings:=Assess(Result{BannerCode:tc.banner,EHLOCode:tc.ehlo})
   found:=false
   for _, f:=range findings {
    if f.Code=="SMTP_GREETING_NOT_ACCEPTED" {
     if found { t.Fatal("duplicate greeting finding") }
     found=true
     if f.Severity!="warning" { t.Fatalf("severity = %q",f.Severity) }
    }
   }
   if found!=tc.want { t.Fatalf("greeting finding = %v, want %v; findings = %+v",found,tc.want,findings) }
  })
 }
}

func TestAssessRejectedGreetingDoesNotInferSTARTTLS(t *testing.T) {
 findings:=Assess(Result{BannerCode:421,EHLOCode:0})
 for _, f:=range findings {
  if f.Code=="STARTTLS_NOT_ADVERTISED" || f.Code=="AUTH_NOT_ADVERTISED_AFTER_TLS" {
   t.Fatalf("inferred policy from rejected greeting: %+v",f)
  }
 }
}
