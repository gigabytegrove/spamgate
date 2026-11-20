package smtpprobe

import (
 "crypto/tls"
 "strings"
)

// tlsEvidenceFindings reports negotiated TLS properties only after the probe
// completed certificate verification. It never equates TLS with SMTP AUTH.
func tlsEvidenceFindings(r Result) []Finding {
 if !r.StartTLSVerified { return nil }
 findings:=[]Finding{}
 if r.TLSVerifiedChains == 0 {
  findings=append(findings,Finding{Code:"TLS_VERIFICATION_EVIDENCE_MISSING",Severity:"warning",Message:"STARTTLS is marked verified but no verified certificate chain was recorded; inspect probe evidence"})
 }
 if r.TLSCipherSuite == "" {
  findings=append(findings,Finding{Code:"TLS_CIPHER_EVIDENCE_MISSING",Severity:"warning",Message:"STARTTLS is marked verified but the negotiated cipher suite was not recorded"})
 } else {
  // The standard library names these suites, including TLS 1.3 suites.
  // Report the observed negotiation without claiming vulnerability scanning.
  if strings.Contains(r.TLSCipherSuite,"_3DES_") || strings.Contains(r.TLSCipherSuite,"_RC4_") || strings.Contains(r.TLSCipherSuite,"_CBC_") {
   findings=append(findings,Finding{Code:"TLS_LEGACY_CIPHER_NEGOTIATED",Severity:"warning",Message:"SMTP TLS negotiated a legacy cipher suite; inspect server TLS policy"})
  }
 }
 if r.TLSMutualAuthentication {
  findings=append(findings,Finding{Code:"TLS_CLIENT_AUTH_EVIDENCE_UNEXPECTED",Severity:"warning",Message:"Read-only SMTP probe reported mutual TLS authentication without supplying a client certificate; inspect diagnostic integrity"})
 }
 return findings
}

// cipherSuiteKnown is a bounded name check for externally constructed Results.
// The probe itself obtains names exclusively from crypto/tls.
func cipherSuiteKnown(name string) bool {
 for _,suite:=range tls.CipherSuites() {
  if suite.Name==name {return true}
 }
 for _,suite:=range tls.InsecureCipherSuites() {
  if suite.Name==name {return true}
 }
 return false
}
