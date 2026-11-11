package smtpprobe

import (
 "crypto/x509"
 "crypto/x509/pkix"
 "reflect"
 "testing"
 "time"
)

func TestCertificateInfoVerifiedLeafMetadata(t *testing.T) {
 now := time.Date(2026,11,11,10,0,0,0,time.UTC)
 cert := &x509.Certificate{
  Subject: pkix.Name{CommonName:"smtp.example.net"},
  Issuer: pkix.Name{CommonName:"Example Issuing CA"},
  DNSNames: []string{"smtp.example.net","mail.example.net"},
  NotBefore: now.Add(-24*time.Hour),
  NotAfter: now.Add(31*24*time.Hour),
 }
 got := certificateInfo(cert,now)
 if got==nil { t.Fatal("missing certificate info") }
 if got.Subject!=cert.Subject.String() || got.Issuer!=cert.Issuer.String() {t.Fatalf("wrong certificate identity: %+v",got)}
 if got.DaysUntilExpiry!=31 || !got.NotAfter.Equal(cert.NotAfter) || !got.NotBefore.Equal(cert.NotBefore) {t.Fatalf("wrong certificate validity: %+v",got)}
 if !reflect.DeepEqual(got.DNSNames,cert.DNSNames) {t.Fatalf("wrong DNS names: %v",got.DNSNames)}
 cert.DNSNames[0]="modified.example.net"
 if got.DNSNames[0]!="smtp.example.net" {t.Fatal("certificate metadata aliases source slice")}
}

func TestCertificateInfoExpiredAndNil(t *testing.T) {
 now:=time.Date(2026,11,11,10,0,0,0,time.UTC)
 if certificateInfo(nil,now)!=nil {t.Fatal("nil certificate must not produce metadata")}
 for _,d:=range []time.Duration{-time.Second,-48*time.Hour} {
  got:=certificateInfo(&x509.Certificate{NotAfter:now.Add(d)},now)
  if got.DaysUntilExpiry>=0 {t.Fatalf("expired certificate reported nonnegative days: %+v",got)}
 }
}
