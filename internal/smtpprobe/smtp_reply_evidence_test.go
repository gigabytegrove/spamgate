package smtpprobe

import (
 "strings"
 "testing"
)

func TestSMTPReplyClassEvidence(t *testing.T) {
 cases := []struct{stage string; code int; want string}{
  {"GREETING", 421, "GREETING_TEMPORARY_REPLY"},
  {"EHLO", 450, "EHLO_TEMPORARY_REPLY"},
  {"STARTTLS", 454, "STARTTLS_TEMPORARY_REPLY"},
  {"POST_TLS_EHLO", 550, "POST_TLS_EHLO_PERMANENT_REPLY"},
  {"EHLO", 554, "EHLO_PERMANENT_REPLY"},
  {"EHLO", 250, ""},
  {"EHLO", 0, ""},
  {"EHLO", 399, ""},
  {"EHLO", 600, ""},
 }
 for _, tc := range cases {
  t.Run(tc.stage+"-"+string(rune(tc.code)), func(t *testing.T) {
   got := smtpReplyClassFinding(tc.stage, tc.code)
   if tc.want == "" {
    if got != nil { t.Fatalf("unexpected finding: %+v",got) }
    return
   }
   if got == nil || got.Code != tc.want || got.Severity != "warning" {
    t.Fatalf("finding = %+v, want %s",got,tc.want)
   }
   if !strings.Contains(got.Message,"no message was submitted") {
    t.Fatalf("finding misrepresents mail delivery: %+v",got)
   }
  })
 }
}

func TestSMTPReplyClassFindingsDoNotInventUnattemptedStages(t *testing.T) {
 r := Result{BannerCode:220,EHLOCode:250,StartTLSReplyCode:454}
 got := smtpReplyClassFindings(r)
 if len(got)!=1 || got[0].Code!="STARTTLS_TEMPORARY_REPLY" { t.Fatalf("got %+v",got) }
}

func TestSMTPReplyClassFindingsPreserveMultipleObservedStages(t *testing.T) {
 r := Result{BannerCode:220,EHLOCode:250,StartTLSReplyCode:220,PostTLSEHLOCode:550}
 got := smtpReplyClassFindings(r)
 if len(got)!=1 || got[0].Code!="POST_TLS_EHLO_PERMANENT_REPLY" { t.Fatalf("got %+v",got) }
}

func TestAssessGreetingReplyClass(t *testing.T) {
 got := Assess(Result{BannerCode:421})
 found := false
 for _, f := range got { if f.Code=="GREETING_TEMPORARY_REPLY" { found=true } }
 if !found { t.Fatalf("missing observed greeting class: %+v",got) }
}
