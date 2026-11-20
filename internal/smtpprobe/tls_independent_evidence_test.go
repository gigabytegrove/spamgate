package smtpprobe

import (
 "crypto/tls"
 "testing"
 "time"
)

func TestTLSVersionIndependentOfCipherEvidence(t *testing.T) {
 for _, tc := range []struct{
  name, version, cipher string
  expected, unexpected []string
 }{
  {"unknown version missing cipher","SSL 3.0","",[]string{"TLS_VERSION_EVIDENCE_UNKNOWN","TLS_CIPHER_EVIDENCE_MISSING"},[]string{"TLS_VERSION_CIPHER_MISMATCH"}},
  {"unknown version unknown cipher","SSL 3.0","NOT_A_CIPHER",[]string{"TLS_VERSION_EVIDENCE_UNKNOWN","TLS_CIPHER_EVIDENCE_UNKNOWN"},[]string{"TLS_VERSION_CIPHER_MISMATCH"}},
  {"obsolete version missing cipher","TLS 1.0","",[]string{"TLS_OBSOLETE_VERSION_NEGOTIATED","TLS_CIPHER_EVIDENCE_MISSING"},nil},
  {"obsolete version unknown cipher","TLS 1.1","NOT_A_CIPHER",[]string{"TLS_OBSOLETE_VERSION_NEGOTIATED","TLS_CIPHER_EVIDENCE_UNKNOWN"},nil},
  {"missing version missing cipher","","",[]string{"TLS_VERSION_EVIDENCE_MISSING","TLS_CIPHER_EVIDENCE_MISSING"},[]string{"TLS_VERSION_EVIDENCE_UNKNOWN"}},
  {"valid version missing cipher","TLS 1.3","",[]string{"TLS_CIPHER_EVIDENCE_MISSING"},[]string{"TLS_VERSION_EVIDENCE_UNKNOWN"}},
  {"valid version matching cipher","TLS 1.3",tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256),nil,[]string{"TLS_VERSION_CIPHER_MISMATCH","TLS_VERSION_EVIDENCE_UNKNOWN","TLS_OBSOLETE_VERSION_NEGOTIATED"}},
 } {
  t.Run(tc.name,func(t *testing.T){
   got:=tlsEvidenceFindings(Result{StartTLSVerified:true,TLSVersion:tc.version,TLSCipherSuite:tc.cipher,TLSVerifiedChains:1,TLSCertificate:&CertificateInfo{NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour)}})
   for _, code:=range tc.expected {if !hasTLSFinding(got,code){t.Errorf("missing %s: %+v",code,got)}}
   for _, code:=range tc.unexpected {if hasTLSFinding(got,code){t.Errorf("unexpected %s: %+v",code,got)}}
  })
 }
}

func TestTLSCertificateEvidenceInvariants(t *testing.T) {
 now:=time.Now().UTC()
 cases:=[]struct{
  name string
  cert *CertificateInfo
  want []string
  absent []string
 }{
  {"valid interval",&CertificateInfo{NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour)},nil,[]string{"TLS_CERTIFICATE_VALIDITY_EVIDENCE_MISSING","TLS_CERTIFICATE_VALIDITY_INCONSISTENT"}},
  {"missing both dates",&CertificateInfo{},[]string{"TLS_CERTIFICATE_VALIDITY_EVIDENCE_MISSING"},nil},
  {"missing not before",&CertificateInfo{NotAfter:now},[]string{"TLS_CERTIFICATE_VALIDITY_EVIDENCE_MISSING"},nil},
  {"reversed interval",&CertificateInfo{NotBefore:now,NotAfter:now.Add(-time.Hour)},[]string{"TLS_CERTIFICATE_VALIDITY_INCONSISTENT"},nil},
  {"zero interval",&CertificateInfo{NotBefore:now,NotAfter:now},[]string{"TLS_CERTIFICATE_VALIDITY_INCONSISTENT"},nil},
  {"invalid negative days",&CertificateInfo{NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),DaysUntilExpiry:-2},[]string{"TLS_CERTIFICATE_EXPIRY_EVIDENCE_INCONSISTENT"},nil},
  {"expired sentinel",&CertificateInfo{NotBefore:now.Add(-2*time.Hour),NotAfter:now.Add(-time.Hour),DaysUntilExpiry:-1},nil,[]string{"TLS_CERTIFICATE_EXPIRY_EVIDENCE_INCONSISTENT"}},
 }
 for _,tc:=range cases {
  t.Run(tc.name,func(t *testing.T){
   got:=tlsEvidenceFindings(Result{StartTLSVerified:true,TLSVersion:"TLS 1.3",TLSCipherSuite:tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256),TLSVerifiedChains:1,TLSCertificate:tc.cert})
   for _,code:=range tc.want {if !hasTLSFinding(got,code){t.Errorf("missing %s: %+v",code,got)}}
   for _,code:=range tc.absent {if hasTLSFinding(got,code){t.Errorf("unexpected %s: %+v",code,got)}}
  })
 }
}

func TestUnverifiedTLSCertificateEvidenceIsNotClaimed(t *testing.T) {
 r:=Result{TLSVersion:"SSL 3.0",TLSCipherSuite:"UNKNOWN",TLSCertificate:&CertificateInfo{DaysUntilExpiry:-20}}
 if got:=tlsEvidenceFindings(r);len(got)!=0 {t.Fatalf("unverified handshake produced findings: %+v",got)}
}
