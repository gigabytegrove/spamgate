package smtpprobe

import (
 "strings"
 "testing"
)

func TestObservedEnhancedStatus(t *testing.T) {
 cases:=[]struct{code int; lines []string; want string}{
  {550,[]string{"5.1.1 User unknown"},"5.1.1"},
  {421,[]string{"4.3.2 Service closing"},"4.3.2"},
  {550,[]string{"5.7.1 Policy","5.7.1 Details"},"5.7.1"},
  {550,[]string{"5.7.1 Policy","5.7.2 Details"},""},
  {550,[]string{"4.7.1 Wrong class"},""},
  {550,[]string{"5.7.1x Invalid"},""},
  {550,[]string{"5.7.1000 Invalid"},""},
  {550,[]string{"5.7. Invalid"},""},
  {550,[]string{"5.7.1 Policy","ordinary text"},""},
  {550,[]string{"5.7.1 Policy",""},""},
  {550,[]string{"5.7.1; Injection"},""},
  {250,[]string{"2.0.0 OK"},"2.0.0"},
  {0,[]string{"5.7.1"},""},
 }
 for i,tc:=range cases {if got:=observedEnhancedStatus(tc.code,tc.lines);got!=tc.want {t.Errorf("case %d: got %q want %q",i,got,tc.want)}}
}

func TestEnhancedReplyFindings(t *testing.T) {
 r:=Result{BannerCode:220,EHLOCode:250,StartTLSReplyCode:454,StartTLSEnhancedCode:"4.7.0",PostTLSEHLOCode:0}
 findings:=enhancedReplyFindings(r)
 if len(findings)!=1 || findings[0].Code!="STARTTLS_ENHANCED_REPLY" || !strings.Contains(findings[0].Message,"4.7.0") {t.Fatalf("unexpected findings: %+v",findings)}
 r.StartTLSEnhancedCode="5.7.0"
 if len(enhancedReplyFindings(r))!=0 {t.Fatal("mismatched class accepted")}
 r.StartTLSEnhancedCode="4.7.0"
 found:=false
 for _,f:=range Assess(r) {if f.Code=="STARTTLS_ENHANCED_REPLY" {found=true}}
 if !found {t.Fatal("assessment dropped enhanced reply evidence")}
}
