package smtpprobe

import (
 "crypto/tls"
 "testing"
)

func TestTLSEvidenceIntegrityAndLegacySuites(t *testing.T) {
 cases := []struct {
  name string
  result Result
  want string
  absent string
 }{
  {"unverified evidence ignored", Result{TLSVersion:"TLS 1.3", TLSCipherSuite:"TLS_RSA_WITH_3DES_EDE_CBC_SHA"}, "", "TLS_LEGACY_CIPHER_NEGOTIATED"},
  {"verified modern tls13", Result{StartTLSVerified:true,TLSVerifiedChains:1,TLSVersion:"TLS 1.3",TLSCipherSuite:tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256)}, "", "TLS_VERSION_CIPHER_MISMATCH"},
  {"tls13 with tls12 cipher", Result{StartTLSVerified:true,TLSVerifiedChains:1,TLSVersion:"TLS 1.3",TLSCipherSuite:tls.CipherSuiteName(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)}, "TLS_VERSION_CIPHER_MISMATCH", ""},
  {"tls12 with tls13 cipher", Result{StartTLSVerified:true,TLSVerifiedChains:1,TLSVersion:"TLS 1.2",TLSCipherSuite:tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256)}, "TLS_VERSION_CIPHER_MISMATCH", ""},
  {"tls12 with tls12 cipher", Result{StartTLSVerified:true,TLSVerifiedChains:1,TLSVersion:"TLS 1.2",TLSCipherSuite:tls.CipherSuiteName(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)}, "", "TLS_VERSION_CIPHER_MISMATCH"},
  {"legacy insecure suite", Result{StartTLSVerified:true,TLSVerifiedChains:1,TLSVersion:"TLS 1.2",TLSCipherSuite:"TLS_RSA_WITH_3DES_EDE_CBC_SHA"}, "TLS_LEGACY_CIPHER_NEGOTIATED", ""},
  {"unknown suite", Result{StartTLSVerified:true,TLSVerifiedChains:1,TLSVersion:"TLS 1.2",TLSCipherSuite:"TLS_UNKNOWN_FAKE"}, "TLS_CIPHER_EVIDENCE_UNKNOWN", ""},
  {"missing chain", Result{StartTLSVerified:true,TLSVersion:"TLS 1.3",TLSCipherSuite:tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256)}, "TLS_VERIFICATION_EVIDENCE_MISSING", ""},
  {"unexpected mutual auth", Result{StartTLSVerified:true,TLSVerifiedChains:1,TLSVersion:"TLS 1.3",TLSCipherSuite:tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256),TLSMutualAuthentication:true}, "TLS_CLIENT_AUTH_EVIDENCE_UNEXPECTED", ""},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T) {
   findings:=tlsEvidenceFindings(tc.result)
   if tc.want!="" && !hasTLSFinding(findings,tc.want) {t.Errorf("missing %s: %+v",tc.want,findings)}
   if tc.absent!="" && hasTLSFinding(findings,tc.absent) {t.Errorf("unexpected %s: %+v",tc.absent,findings)}
  })
 }
}
