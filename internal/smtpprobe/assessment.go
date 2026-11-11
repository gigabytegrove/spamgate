package smtpprobe

import (
 "fmt"
 "strings"
)

// Finding is a diagnostic observation, not a production mail-host compliance verdict.
type Finding struct {
 Code string `json:"code"`
 Severity string `json:"severity"`
 Message string `json:"message"`
}

// Assess reports observations only; it never asserts that a server accepted
// credentials, that delivery succeeded, or that its TLS policy is compliant.
func Assess(r Result) []Finding {
 findings := []Finding{}
 if r.EHLOCode != 250 { return findings }
 if len(r.AuthMechanisms) > 0 {
  findings = append(findings, Finding{
   Code:"AUTH_ADVERTISED_BEFORE_TLS", Severity:"warning",
   Message:"SMTP AUTH is advertised before STARTTLS; verify the server refuses unencrypted credential submission",
  })
 }
 if !r.StartTLSAdvertised {
  findings = append(findings, Finding{
   Code:"STARTTLS_NOT_ADVERTISED", Severity:"warning",
   Message:"Server did not advertise STARTTLS in its initial EHLO response",
  })
 }
 if r.StartTLSVerified {
  if r.TLSVersion == "TLS 1.2" {
   findings = append(findings, Finding{
    Code:"TLS_LEGACY_VERSION_NEGOTIATED", Severity:"info",
    Message:"The diagnostic negotiated TLS 1.2; this alone does not prove the server lacks TLS 1.3",
   })
  }
  if r.PostTLSEHLOCode == 250 && len(r.AuthMechanisms) > 0 && len(r.PostTLSAuthMechanisms) == 0 {
   findings = append(findings, Finding{
    Code:"AUTH_NOT_ADVERTISED_AFTER_TLS", Severity:"warning",
    Message:"AUTH was advertised before STARTTLS but not after the verified TLS handshake; inspect SMTP submission policy",
   })
  }
  if r.PostTLSEHLOCode == 250 {
   for _,mechanism := range r.PostTLSAuthMechanisms {
    if strings.EqualFold(mechanism,"PLAIN") || strings.EqualFold(mechanism,"LOGIN") {
     // These mechanisms are not intrinsically unsafe inside verified TLS.
     // Never label them as credential leakage.
     break
    }
   }
  }
  if r.TLSCertificate != nil && r.TLSCertificate.DaysUntilExpiry <= 14 {
   findings = append(findings, Finding{
    Code:"TLS_CERTIFICATE_EXPIRING", Severity:"warning",
    Message:fmt.Sprintf("Verified SMTP TLS certificate expires in %d day(s)",r.TLSCertificate.DaysUntilExpiry),
   })
  }
 }
 return findings
}
