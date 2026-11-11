package smtpprobe

import (
 "strings"
 "context"
 "time"
 "testing"
)

func findingCodes(findings []Finding) map[string]bool {
 codes:=map[string]bool{}
 for _,f:=range findings { codes[f.Code]=true }
 return codes
}
func TestAssessPlaintextAuthAndMissingTLS(t *testing.T) {
 r:=Result{EHLOCode:250,AuthMechanisms:[]string{"PLAIN"},StartTLSAdvertised:false}
 codes:=findingCodes(Assess(r))
 if !codes["AUTH_ADVERTISED_BEFORE_TLS"] || !codes["STARTTLS_NOT_ADVERTISED"] {t.Fatalf("missing expected warnings: %v",codes)}
}
func TestAssessTLSCertificateExpiry(t *testing.T) {
 for _,tc:=range []struct{days int; warn bool}{{0,true},{7,true},{14,true},{15,false},{45,false}} {
  r:=Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,TLSCertificate:&CertificateInfo{DaysUntilExpiry:tc.days}}
  findings:=Assess(r)
  got:=findingCodes(findings)["TLS_CERTIFICATE_EXPIRING"]
  if got!=tc.warn {t.Errorf("days=%d warning=%v want=%v",tc.days,got,tc.warn)}
  if got && !strings.Contains(findings[0].Message,"day(s)") {t.Fatalf("unhelpful expiry finding: %+v",findings)}
 }
}
func TestAssessAvoidsUnsupportedClaims(t *testing.T) {
 for _,r:=range []Result{
  {},
  {EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true},
  {EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:false},
 } {
  if findings:=Assess(r);len(findings)!=0 {t.Errorf("unexpected findings for %+v: %+v",r,findings)}
 }
}
func TestProbeIncludesSecurityFindings(t *testing.T) {
 // A successful plaintext-only diagnostic must report observations, not silently
 // suppress them because the caller explicitly permitted inspection without TLS.
 addr,_:=server(t,"250-test\r\n250 AUTH PLAIN\r\n")
 r,err:=Probe(context.Background(),Options{Address:addr,Timeout:time.Second,RequireTLS:false})
 if err!=nil {t.Fatal(err)}
 codes:=findingCodes(r.Findings)
 if !codes["STARTTLS_NOT_ADVERTISED"] || !codes["AUTH_ADVERTISED_BEFORE_TLS"] {t.Fatalf("missing findings: %+v",r.Findings)}
}


func TestAssessPostTLSAuthCapabilityChanges(t *testing.T) {
 cases:=[]struct{
  name string
  result Result
  want bool
 }{
  {"missing after verified TLS",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,AuthMechanisms:[]string{"PLAIN"},PostTLSEHLOCode:250},true},
  {"present after verified TLS",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,AuthMechanisms:[]string{"PLAIN"},PostTLSEHLOCode:250,PostTLSAuthMechanisms:[]string{"PLAIN"}},false},
  {"not advertised initially",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250},false},
  {"post TLS EHLO failed",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,AuthMechanisms:[]string{"PLAIN"},PostTLSEHLOCode:550},false},
  {"TLS unverified",Result{EHLOCode:250,StartTLSAdvertised:true,AuthMechanisms:[]string{"PLAIN"},PostTLSEHLOCode:250},false},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   got:=findingCodes(Assess(tc.result))["AUTH_NOT_ADVERTISED_AFTER_TLS"]
   if got!=tc.want {t.Fatalf("AUTH regression=%v, want %v",got,tc.want)}
  })
 }
}

func TestAssessNegotiatedTLSVersion(t *testing.T) {
 for _,tc:=range []struct{version string;verified,want bool}{
  {"TLS 1.2",true,true},
  {"TLS 1.3",true,false},
  {"TLS 1.2",false,false},
  {"",true,false},
 }{
  r:=Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:tc.verified,TLSVersion:tc.version}
  got:=findingCodes(Assess(r))["TLS_LEGACY_VERSION_NEGOTIATED"]
  if got!=tc.want {t.Errorf("version=%q verified=%v got=%v want=%v",tc.version,tc.verified,got,tc.want)}
 }
}
