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
