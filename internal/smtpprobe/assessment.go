package smtpprobe

import "fmt"

// Finding is a diagnostic observation, not a production mail-host compliance verdict.
type Finding struct {
 Code string `json:"code"`
 Severity string `json:"severity"`
 Message string `json:"message"`
}

// Assess reports protocol observations without attempting authentication or delivery.
// It deliberately does not claim that plaintext AUTH was used or credentials leaked.
func Assess(r Result) []Finding {
 findings:=[]Finding{}
 if r.EHLOCode!=250 { return findings }
 if len(r.AuthMechanisms)>0 {
  findings=append(findings,Finding{
   Code:"AUTH_ADVERTISED_BEFORE_TLS",Severity:"warning",
   Message:"SMTP AUTH is advertised before STARTTLS; inspect server policy to ensure plaintext credentials cannot be accepted",
  })
 }
 if !r.StartTLSAdvertised {
  findings=append(findings,Finding{
   Code:"STARTTLS_NOT_ADVERTISED",Severity:"warning",
   Message:"Server did not advertise STARTTLS in its initial EHLO response",
  })
 }
 if r.StartTLSVerified && r.TLSCertificate!=nil && r.TLSCertificate.DaysUntilExpiry<=14 {
  findings=append(findings,Finding{
   Code:"TLS_CERTIFICATE_EXPIRING",Severity:"warning",
   Message:fmt.Sprintf("Verified SMTP TLS certificate expires in %d day(s)",r.TLSCertificate.DaysUntilExpiry),
  })
 }
 return findings
}
