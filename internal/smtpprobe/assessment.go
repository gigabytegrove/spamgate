package smtpprobe

import (
 "fmt"
 "strings"
)

// Finding is an observed SMTP behavior, not a production compliance verdict.
type Finding struct {
 Code string `json:"code"`
 Severity string `json:"severity"`
 Message string `json:"message"`
}

// mechanismSet normalizes advertised mechanisms for comparison only. This
// diagnostic never attempts authentication or sends credentials.
func mechanismSet(mechanisms []string) map[string]bool {
 out := make(map[string]bool, len(mechanisms))
 for _, mechanism := range mechanisms {
  name := strings.ToUpper(strings.TrimSpace(mechanism))
  if name != "" { out[name] = true }
 }
 return out
}

// Assess only reports protocol observations. An advertised AUTH mechanism does
// not prove the server accepts credentials, and a verified STARTTLS connection
// does not prove that delivery or SMTP authentication works.
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
 if !r.StartTLSVerified { return findings }
 if r.TLSVersion == "TLS 1.2" {
  findings = append(findings, Finding{
   Code:"TLS_LEGACY_VERSION_NEGOTIATED", Severity:"info",
   Message:"The diagnostic negotiated TLS 1.2; this alone does not prove the server lacks TLS 1.3",
  })
 }
 if r.PostTLSEHLOCode == 250 {
  if r.PostTLSStartTLSAdvertised {
   findings = append(findings, Finding{
    Code:"STARTTLS_ADVERTISED_AFTER_TLS", Severity:"warning",
    Message:"Server still advertises STARTTLS after a verified TLS handshake; inspect RFC 3207 capability handling",
   })
  }
  before := mechanismSet(r.AuthMechanisms)
  after := mechanismSet(r.PostTLSAuthMechanisms)
  if len(before) > 0 && len(after) == 0 {
   findings = append(findings, Finding{
    Code:"AUTH_NOT_ADVERTISED_AFTER_TLS", Severity:"warning",
    Message:"AUTH was advertised before STARTTLS but not after the verified TLS handshake; inspect SMTP submission policy",
   })
  } else if len(before) > 0 {
   removed := []string{}
   for mechanism := range before {
    if !after[mechanism] { removed = append(removed, mechanism) }
   }
   if len(removed) > 0 {
    // Do not report specific mechanisms: that would expose unstable ordering
    // in diagnostic JSON, and changes in advertisement need operator review.
    findings = append(findings, Finding{
     Code:"AUTH_MECHANISMS_CHANGED_AFTER_TLS", Severity:"info",
     Message:"One or more AUTH mechanisms advertised before STARTTLS are absent after verified TLS; compare server submission policy",
    })
   }
  }
 }
 if r.TLSCertificate != nil && r.TLSCertificate.DaysUntilExpiry <= 14 {
  findings = append(findings, Finding{
   Code:"TLS_CERTIFICATE_EXPIRING", Severity:"warning",
   Message:fmt.Sprintf("Verified SMTP TLS certificate expires in %d day(s)",r.TLSCertificate.DaysUntilExpiry),
  })
 }
 return findings
}
