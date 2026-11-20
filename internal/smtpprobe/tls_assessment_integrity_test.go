package smtpprobe

import (
 "crypto/tls"
 "testing"
)

func TestAssessIncludesTLSIntegrityEvidence(t *testing.T) {
 r:=Result{
  BannerCode:220, EHLOCode:250, StartTLSAdvertised:true,
  StartTLSReplyCode:220, StartTLSVerified:true,
  TLSVersion:"TLS 1.3",
  TLSCipherSuite:tls.CipherSuiteName(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
  TLSVerifiedChains:0,
  PostTLSEHLOCode:250,
 }
 findings:=Assess(r)
 for _,code:=range []string{
  "TLS_VERSION_CIPHER_MISMATCH",
  "TLS_VERIFICATION_EVIDENCE_MISSING",
  "TLS_CERTIFICATE_EVIDENCE_MISSING",
 } {
  if !hasTLSFinding(findings,code) {t.Errorf("Assess lost %s: %+v",code,findings)}
 }
}

func TestAssessDoesNotReportTLSNegotiationOnFailedHandshake(t *testing.T) {
 r:=Result{BannerCode:220,EHLOCode:250,StartTLSAdvertised:true,StartTLSReplyCode:220,
  TLSVersion:"TLS 1.0",TLSCipherSuite:"TLS_UNKNOWN",TLSVerifiedChains:-1}
 for _,finding:=range Assess(r) {
  switch finding.Code {
  case "TLS_OBSOLETE_VERSION_NEGOTIATED", "TLS_VERSION_CIPHER_MISMATCH", "TLS_VERSION_EVIDENCE_UNKNOWN", "TLS_VERIFICATION_EVIDENCE_MISSING":
   t.Errorf("failed handshake reported TLS negotiation: %+v",finding)
  }
 }
}
