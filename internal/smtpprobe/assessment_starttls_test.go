package smtpprobe

import "testing"

// A successful TLS handshake is not enough: RFC 3207 requires the server to
// discard pre-TLS knowledge and STARTTLS must not be advertised after TLS.
func TestAssessSTARTTLSAfterVerifiedTLS(t *testing.T) {
 cases := []struct {
  name string
  result Result
  want bool
 }{
  {"advertised again",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250,PostTLSStartTLSAdvertised:true},true},
  {"normal post TLS EHLO",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:250},false},
  {"unverified TLS",Result{EHLOCode:250,StartTLSAdvertised:true,PostTLSEHLOCode:250,PostTLSStartTLSAdvertised:true},false},
  {"post TLS EHLO rejected",Result{EHLOCode:250,StartTLSAdvertised:true,StartTLSVerified:true,PostTLSEHLOCode:550,PostTLSStartTLSAdvertised:true},false},
  {"initial EHLO rejected",Result{EHLOCode:550,StartTLSVerified:true,PostTLSEHLOCode:250,PostTLSStartTLSAdvertised:true},false},
 }
 for _,tc := range cases {
  t.Run(tc.name,func(t *testing.T){
   got := findingCodes(Assess(tc.result))["STARTTLS_ADVERTISED_AFTER_TLS"]
   if got != tc.want { t.Fatalf("finding=%v want=%v",got,tc.want) }
  })
 }
}

func TestCapabilitiesPostTLSSTARTTLS(t *testing.T) {
 advertised, auth := capabilities([]string{"server.example","SIZE 12345","STARTTLS","AUTH PLAIN LOGIN"})
 if !advertised { t.Fatal("STARTTLS capability not parsed") }
 if len(auth)!=2 || auth[0]!="PLAIN" || auth[1]!="LOGIN" { t.Fatalf("AUTH capabilities=%v",auth) }
}
