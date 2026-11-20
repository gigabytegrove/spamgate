package smtpprobe

import (
 "crypto/tls"
 "strings"
)

// tlsEvidenceFindings reports observed negotiation evidence. A successful
// handshake is not evidence of SMTP AUTH or successful mail delivery.
func tlsEvidenceFindings(r Result) []Finding {
 if !r.StartTLSVerified { return nil }
 findings := make([]Finding, 0, 6)
 add := func(code, message string) {
  findings = append(findings, Finding{Code:code, Severity:"warning", Message:message})
 }
 if r.TLSVerifiedChains == 0 {
  add("TLS_VERIFICATION_EVIDENCE_MISSING", "STARTTLS is marked verified but no verified certificate chain was recorded; inspect probe evidence")
 }
 if r.TLSCipherSuite == "" {
  add("TLS_CIPHER_EVIDENCE_MISSING", "STARTTLS is marked verified but the negotiated cipher suite was not recorded")
 } else {
  suite, known, insecure := lookupCipherSuite(r.TLSCipherSuite)
  if !known {
   add("TLS_CIPHER_EVIDENCE_UNKNOWN", "Recorded TLS cipher suite is not recognized by the local TLS implementation; inspect diagnostic integrity")
  } else {
   if insecure || strings.Contains(suite.Name, "_CBC_") {
    add("TLS_LEGACY_CIPHER_NEGOTIATED", "SMTP TLS negotiated a legacy cipher suite; inspect server TLS policy")
   }
   // TLS 1.3 has a distinct cipher suite namespace. A contradictory
   // result must be diagnosed rather than treated as successful evidence.
   tls13Suite := strings.HasPrefix(suite.Name, "TLS_AES_") || suite.Name == "TLS_CHACHA20_POLY1305_SHA256"
   if (r.TLSVersion == "TLS 1.3" && !tls13Suite) ||
    (r.TLSVersion == "TLS 1.2" && tls13Suite) {
    add("TLS_VERSION_CIPHER_MISMATCH", "Recorded TLS version and cipher suite are inconsistent; inspect diagnostic integrity")
   }
  }
 }
 if r.TLSMutualAuthentication {
  add("TLS_CLIENT_AUTH_EVIDENCE_UNEXPECTED", "Read-only SMTP probe reported mutual TLS authentication without supplying a client certificate; inspect diagnostic integrity")
 }
 return findings
}

func lookupCipherSuite(name string) (tls.CipherSuite, bool, bool) {
 for _, suite := range tls.CipherSuites() {
  if suite.Name == name { return *suite, true, false }
 }
 for _, suite := range tls.InsecureCipherSuites() {
  if suite.Name == name { return *suite, true, true }
 }
 return tls.CipherSuite{}, false, false
}

func cipherSuiteKnown(name string) bool {
 _, known, _ := lookupCipherSuite(name)
 return known
}
