package transport

import (
 "net"
 "testing"
)

func TestParseSMTPTrustedNetworkNoSilentExpansion(t *testing.T) {
 for _, tc := range []struct { value string; ok bool }{
  {"192.0.2.0/24", true},
  {"192.0.2.5/32", true},
  {"192.0.2.5/24", false},
  {"192.0.2.1/0", false},
  {"0.0.0.0/0", true},
  {"2001:db8::/64", true},
  {"2001:db8::5/128", true},
  {"2001:db8::5/64", false},
  {"::/0", true},
  {"192.0.2.0/33", false},
  {"192.0.2.0/24 ", false},
  {"", false},
 } {
  t.Run(tc.value,func(t *testing.T){
   n,err:=parseSMTPTrustedNetwork(tc.value)
   if (err==nil)!=tc.ok {t.Fatalf("parse(%q) network=%v error=%v want success=%v",tc.value,n,err,tc.ok)}
  })
 }
}

func TestSMTPFromEnvRejectsNonCanonicalTrustedCIDR(t *testing.T) {
 t.Setenv("SPAMGATE_SMTP_LISTEN","127.0.0.1:0")
 t.Setenv("SPAMGATE_ALLOWED_RECIPIENT_DOMAINS","example.com")
 for _,tc:=range []struct{cidr string; ok bool}{
  {"192.0.2.5/24",false},
  {"192.0.2.0/24",true},
  {"192.0.2.5",true},
  {"2001:db8::5/64",false},
  {"2001:db8::/64",true},
  {"2001:db8::5",true},
 } {
  t.Run(tc.cidr,func(t *testing.T){
   t.Setenv("SPAMGATE_SMTP_TRUSTED_CIDRS",tc.cidr)
   s,err:=SMTPFromEnv(nil,&Relay{})
   if (err==nil)!=tc.ok {t.Fatalf("CIDR %q: s=%v err=%v want success=%v",tc.cidr,s,err,tc.ok)}
   if tc.ok && len(s.CIDRs)!=1 {t.Fatal("expected one network")}
  })
 }
}

func TestTrustedNetworkDoesNotIncludeAdjacentHosts(t *testing.T) {
 n,err:=parseSMTPTrustedNetwork("192.0.2.5/32")
 if err!=nil {t.Fatal(err)}
 if n.Contains(net.ParseIP("192.0.2.6")) {t.Fatal("adjacent host trusted")}
}
