package smtpprobe

import (
 "context"
 "strings"
 "testing"
 "time"
)

func TestAssessSTARTTLSCommandRefusalEvidence(t *testing.T) {
 cases := []struct {
  name string
  r Result
  want bool
 }{
  {"temporary refusal", Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSReplyCode:454},true},
  {"permanent refusal", Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSReplyCode:550},true},
  {"successful reply without verified TLS", Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSReplyCode:220},false},
  {"no reply", Result{EHLOCode:250,StartTLSAdvertised:true},false},
  {"no advertisement", Result{EHLOCode:250,StartTLSReplyCode:454},false},
  {"EHLO rejected", Result{EHLOCode:550,StartTLSAdvertised:true,StartTLSReplyCode:454},false},
  {"verified TLS", Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSReplyCode:220,StartTLSVerified:true,PostTLSEHLOCode:250},false},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   codes:=findingCodes(Assess(tc.r))
   if codes["STARTTLS_COMMAND_REJECTED"]!=tc.want {
    t.Fatalf("findings=%+v want refusal=%v",Assess(tc.r),tc.want)
   }
  })
 }
}

func TestProbeSTARTTLSRefusalRetainsReplyAndNeverSubmitsMail(t *testing.T) {
 addr, commands:=server(t,"250-test\\r\\n250 STARTTLS\\r\\n")
 result,err:=Probe(context.Background(),Options{Address:addr,Timeout:2*time.Second,RequireTLS:true})
 if err==nil || !strings.Contains(err.Error(),"454") { t.Fatalf("expected refusal: %v",err) }
 if result.StartTLSReplyCode!=454 || result.StartTLSVerified { t.Fatalf("invalid TLS evidence: %+v",result) }
 if !findingCodes(result.Findings)["STARTTLS_COMMAND_REJECTED"] { t.Fatalf("missing refusal diagnostic: %+v",result.Findings) }
 seen:=false
 for command:=range commands {
  if command=="STARTTLS" { seen=true;continue }
  if !strings.HasPrefix(command,"EHLO ") { t.Fatalf("unexpected SMTP command %q",command) }
 }
 if !seen { t.Fatal("STARTTLS was not sent") }
}
