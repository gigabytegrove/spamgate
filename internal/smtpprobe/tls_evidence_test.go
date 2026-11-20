package smtpprobe

import (
 "crypto/tls"
 "testing"
)

func hasTLSFinding(findings []Finding, code string) bool {
 for _,finding:=range findings {if finding.Code==code{return true}}
 return false
}

func TestTLSEvidenceFindings(t *testing.T) {
 tests:=[]struct{name string;result Result;want []string;absent []string}{
  {"unverified",Result{TLSCipherSuite:"TLS_RSA_WITH_3DES_EDE_CBC_SHA"},nil,[]string{"TLS_LEGACY_CIPHER_NEGOTIATED"}},
  {"missing chain",Result{StartTLSVerified:true,TLSCipherSuite:tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256)},[]string{"TLS_VERIFICATION_EVIDENCE_MISSING"},nil},
  {"missing cipher",Result{StartTLSVerified:true,TLSVerifiedChains:1},[]string{"TLS_CIPHER_EVIDENCE_MISSING"},nil},
  {"modern",Result{StartTLSVerified:true,TLSVerifiedChains:1,TLSCipherSuite:tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256)},nil,[]string{"TLS_CIPHER_EVIDENCE_MISSING","TLS_LEGACY_CIPHER_NEGOTIATED"}},
  {"legacy",Result{StartTLSVerified:true,TLSVerifiedChains:1,TLSCipherSuite:"TLS_RSA_WITH_3DES_EDE_CBC_SHA"},[]string{"TLS_LEGACY_CIPHER_NEGOTIATED"},nil},
  {"unexpected client auth",Result{StartTLSVerified:true,TLSVerifiedChains:1,TLSCipherSuite:tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256),TLSMutualAuthentication:true},[]string{"TLS_CLIENT_AUTH_EVIDENCE_UNEXPECTED"},nil},
 }
 for _,tt:=range tests {
  t.Run(tt.name,func(t *testing.T){
   findings:=tlsEvidenceFindings(tt.result)
   for _,code:=range tt.want {if !hasTLSFinding(findings,code){t.Errorf("missing %s in %+v",code,findings)}}
   for _,code:=range tt.absent {if hasTLSFinding(findings,code){t.Errorf("unexpected %s in %+v",code,findings)}}
  })
 }
}
