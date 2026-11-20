package smtpprobe

import (
 "crypto/tls"
 "testing"
)

func TestTLSVersionEvidenceMatrix(t *testing.T) {
 modern13 := tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256)
 modern12 := tls.CipherSuiteName(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
 cases := []struct {
  name, version, cipher string
  chain int
  certificate bool
  want, absent []string
 }{
  {"tls13 compatible", "TLS 1.3", modern13, 1, true, nil, []string{"TLS_VERSION_CIPHER_MISMATCH", "TLS_VERSION_EVIDENCE_MISSING"}},
  {"tls12 compatible", "TLS 1.2", modern12, 1, true, nil, []string{"TLS_VERSION_CIPHER_MISMATCH"}},
  {"tls13 with tls12 cipher", "TLS 1.3", modern12, 1, true, []string{"TLS_VERSION_CIPHER_MISMATCH"}, nil},
  {"tls12 with tls13 cipher", "TLS 1.2", modern13, 1, true, []string{"TLS_VERSION_CIPHER_MISMATCH"}, nil},
  {"tls11 with modern suite", "TLS 1.1", modern12, 1, true, []string{"TLS_VERSION_CIPHER_MISMATCH", "TLS_OBSOLETE_VERSION_NEGOTIATED"}, nil},
  {"tls10 with modern suite", "TLS 1.0", modern12, 1, true, []string{"TLS_VERSION_CIPHER_MISMATCH", "TLS_OBSOLETE_VERSION_NEGOTIATED"}, nil},
  {"missing version", "", modern13, 1, true, []string{"TLS_VERSION_EVIDENCE_MISSING"}, []string{"TLS_VERSION_CIPHER_MISMATCH"}},
  {"unknown version", "SSL 3.0", modern13, 1, true, []string{"TLS_VERSION_EVIDENCE_UNKNOWN"}, []string{"TLS_VERSION_CIPHER_MISMATCH"}},
  {"missing leaf", "TLS 1.3", modern13, 1, false, []string{"TLS_CERTIFICATE_EVIDENCE_MISSING"}, nil},
  {"missing chains", "TLS 1.3", modern13, 0, true, []string{"TLS_VERIFICATION_EVIDENCE_MISSING"}, nil},
  {"negative chains", "TLS 1.3", modern13, -1, true, []string{"TLS_VERIFICATION_EVIDENCE_MISSING"}, nil},
  {"missing suite", "TLS 1.3", "", 1, true, []string{"TLS_CIPHER_EVIDENCE_MISSING"}, nil},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   r := Result{StartTLSVerified:true, TLSVersion:tc.version, TLSCipherSuite:tc.cipher, TLSVerifiedChains:tc.chain}
   if tc.certificate {r.TLSCertificate=&CertificateInfo{}}
   got:=tlsEvidenceFindings(r)
   for _,code:=range tc.want {if !hasTLSFinding(got,code){t.Errorf("missing %s: %+v",code,got)}}
   for _,code:=range tc.absent {if hasTLSFinding(got,code){t.Errorf("unexpected %s: %+v",code,got)}}
  })
 }
}

func TestUnverifiedTLSDoesNotClaimNegotiationEvidence(t *testing.T) {
 r:=Result{TLSVersion:"TLS 1.0",TLSCipherSuite:"TLS_UNKNOWN",TLSVerifiedChains:-1}
 if findings:=tlsEvidenceFindings(r);len(findings)!=0 {t.Fatalf("unverified handshake yielded findings: %+v",findings)}
}
