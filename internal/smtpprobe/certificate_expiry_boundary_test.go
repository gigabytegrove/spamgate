package smtpprobe

import (
 "crypto/x509"
 "testing"
 "time"
)

func TestCertificateRemainingDaysBoundaries(t *testing.T) {
 now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
 cases := []struct{name string; remaining time.Duration; want int}{
  {"expired by one nanosecond", -time.Nanosecond, -1},
  {"expires now", 0, 0},
  {"expires in one nanosecond", time.Nanosecond, 1},
  {"expires in one hour", time.Hour, 1},
  {"exactly one day", 24*time.Hour, 1},
  {"one day and one nanosecond", 24*time.Hour+time.Nanosecond, 2},
  {"exactly fourteen days", 14*24*time.Hour, 14},
  {"fourteen days and one nanosecond", 14*24*time.Hour+time.Nanosecond, 15},
 }
 for _, tc := range cases {
  t.Run(tc.name, func(t *testing.T) {
   got := certificateInfo(&x509.Certificate{NotAfter:now.Add(tc.remaining)},now)
   if got == nil || got.DaysUntilExpiry != tc.want { t.Fatalf("days = %v, want %d",got,tc.want) }
  })
 }
}

func TestCertificateExpiryFindingsDistinct(t *testing.T) {
 cases := []struct{name string; days int; expired, expiring bool}{
  {"expired", -1, true, false},
  {"expires now", 0, false, true},
  {"last day", 1, false, true},
  {"threshold", 14, false, true},
  {"outside threshold", 15, false, false},
 }
 for _, tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   r := Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250,TLSCertificate:&CertificateInfo{DaysUntilExpiry:tc.days}}
   var expired,expiring bool
   for _,f := range Assess(r) {
    if f.Code=="TLS_CERTIFICATE_EXPIRED" { expired=true }
    if f.Code=="TLS_CERTIFICATE_EXPIRING" { expiring=true }
   }
   if expired!=tc.expired || expiring!=tc.expiring {t.Fatalf("expired=%v expiring=%v, want %v %v",expired,expiring,tc.expired,tc.expiring)}
  })
 }
}
