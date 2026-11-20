package smtpprobe

import (
 "crypto/tls"
 "testing"
 "time"
)

func TestTLSExpiryEvidenceUsesObservationTime(t *testing.T) {
 observed := time.Date(2026, 11, 20, 20, 0, 0, 0, time.UTC)
 cases := []struct {
  name string
  notAfter time.Time
  days int
  want bool
 }{
  {"future certificate", observed.Add(48*time.Hour), 2, false},
  {"expired certificate", observed.Add(-time.Second), -1, false},
  {"future with expired sentinel", observed.Add(time.Hour), -1, true},
  {"expired with nonnegative days", observed.Add(-time.Second), 0, true},
  {"expired with positive days", observed.Add(-time.Hour), 1, true},
  {"future with invalid negative days", observed.Add(time.Hour), -2, true},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   r := Result{
    StartTLSVerified: true,
    TLSObservedAt: observed,
    TLSVersion: "TLS 1.3",
    TLSCipherSuite: tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256),
    TLSVerifiedChains: 1,
    TLSCertificate: &CertificateInfo{
     NotBefore: observed.Add(-24*time.Hour),
     NotAfter: tc.notAfter,
     DaysUntilExpiry: tc.days,
    },
   }
   got := tlsEvidenceFindings(r)
   count := 0
   for _, finding := range got {
    if finding.Code == "TLS_CERTIFICATE_EXPIRY_EVIDENCE_INCONSISTENT" { count++ }
   }
   if tc.want && count != 1 { t.Fatalf("expected exactly one expiry inconsistency, got %d: %+v",count,got) }
   if !tc.want && count != 0 { t.Fatalf("unexpected expiry inconsistency: %+v",got) }
  })
 }
}

func TestTLSExpiryArchivedEvidenceDoesNotUseCurrentClock(t *testing.T) {
 observed := time.Date(2020,1,1,0,0,0,0,time.UTC)
 r := Result{
  StartTLSVerified:true, TLSObservedAt:observed,
  TLSVersion:"TLS 1.3",TLSCipherSuite:tls.CipherSuiteName(tls.TLS_AES_128_GCM_SHA256),
  TLSVerifiedChains:1,
  TLSCertificate:&CertificateInfo{
   NotBefore:observed.Add(-time.Hour),
   NotAfter:observed.Add(48*time.Hour),
   DaysUntilExpiry:2,
  },
 }
 for _, finding := range tlsEvidenceFindings(r) {
  if finding.Code=="TLS_CERTIFICATE_EXPIRY_EVIDENCE_INCONSISTENT" {
   t.Fatalf("historical evidence must use observation time: %+v",finding)
  }
 }
}
