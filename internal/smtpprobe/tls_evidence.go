package smtpprobe

import (
 "crypto/tls"
 "strings"
)

// tlsEvidenceFindings reports observed negotiation evidence. A successful
// handshake is not evidence of SMTP AUTH or successful mail delivery.
func tlsEvidenceFindings(r Result) []Finding {
 if !r.StartTLSVerified { return nil }
 findings := make([]Finding, 0, 10)
 add := func(code, message string) {
  findings = append(findings, Finding{Code:code, Severity:"warning", Message:message})
 }
 if r.TLSVerifiedChains <= 0 {
  add("TLS_VERIFICATION_EVIDENCE_MISSING", "STARTTLS is marked verified but no verified certificate chain was recorded; inspect probe evidence")
 }
 version := uint16(0)
 switch r.TLSVersion {
 case "TLS 1.0": version = tls.VersionTLS10
 case "TLS 1.1": version = tls.VersionTLS11
 case "TLS 1.2": version = tls.VersionTLS12
 case "TLS 1.3": version = tls.VersionTLS13
 case "": add("TLS_VERSION_EVIDENCE_MISSING", "STARTTLS is marked verified but the negotiated TLS protocol version was not recorded")
 default: add("TLS_VERSION_EVIDENCE_UNKNOWN", "Recorded TLS protocol version is not recognized; inspect diagnostic integrity")
 }
 if version != 0 && version < tls.VersionTLS12 {
  add("TLS_OBSOLETE_VERSION_NEGOTIATED", "Recorded SMTP TLS protocol is older than TLS 1.2; inspect server policy and diagnostic integrity")
 }
 if r.TLSCertificate == nil {
  add("TLS_CERTIFICATE_EVIDENCE_MISSING", "STARTTLS is marked verified but no peer leaf certificate metadata was recorded")
 } else {
  cert := r.TLSCertificate
  if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
   add("TLS_CERTIFICATE_VALIDITY_EVIDENCE_MISSING", "Verified SMTP TLS leaf certificate has incomplete validity timestamps; inspect diagnostic integrity")
  } else if !cert.NotAfter.After(cert.NotBefore) {
   add("TLS_CERTIFICATE_VALIDITY_INCONSISTENT", "Verified SMTP TLS leaf certificate has an invalid validity interval; inspect diagnostic integrity")
  }
  if cert.DaysUntilExpiry < -1 {
   add("TLS_CERTIFICATE_EXPIRY_EVIDENCE_INCONSISTENT", "Certificate expiry evidence contains an invalid negative day count; inspect diagnostic integrity")
  }
  // DaysUntilExpiry is a rounded observation, not a second source of
  // certificate validity. A future NotAfter with an expired sentinel (or
  // an already-expired NotAfter with a positive count) is contradictory.
  // Avoid wall-clock assumptions when inspecting archived diagnostic data:
  // use the recorded observation timestamp when it is available.
  if !r.TLSObservedAt.IsZero() && !cert.NotAfter.IsZero() {
   expired := !cert.NotAfter.After(r.TLSObservedAt)
   if (expired && cert.DaysUntilExpiry >= 0) || (!expired && cert.DaysUntilExpiry < 0) {
    add("TLS_CERTIFICATE_EXPIRY_EVIDENCE_INCONSISTENT", "Certificate expiry count contradicts recorded TLS observation time; inspect diagnostic integrity")
   }
  }
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
   // SupportedVersions is authoritative for each suite. Name prefixes alone
   // cannot detect TLS 1.0/1.1 or future version/suite incompatibility.
   if version != 0 {
    supported := false
    for _, candidate := range suite.SupportedVersions {
     if candidate == version { supported = true; break }
    }
    if !supported {
     add("TLS_VERSION_CIPHER_MISMATCH", "Recorded TLS version and cipher suite are inconsistent; inspect diagnostic integrity")
    }
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
