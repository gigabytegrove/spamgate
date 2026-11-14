package transport

import "testing"

func TestParseSMTPXForwardHelo(t *testing.T) {
 cases := []struct { in, want string; ok bool }{
  {"mail.example.org", "mail.example.org", true},
  {"MX-01.Example.org", "MX-01.Example.org", true},
  {"localhost", "localhost", true},
  {"[192.0.2.5]", "[192.0.2.5]", true},
  {"[IPv6:2001:db8::5]", "[IPv6:2001:db8::5]", true},
  {"[UNAVAILABLE]", "", true},
  {"[TEMPUNAVAIL]", "", true},
  {"", "", false},
  {"mail.example.org\r", "", false},
  {"mail.example.org\nX-Injected:yes", "", false},
  {"mail.example.org\t", "", false},
  {"mail.example.org other", "", false},
  {"mail_example.org", "", false},
  {"-mail.example.org", "", false},
  {"mail-.example.org", "", false},
  {"mail..example.org", "", false},
  {"mail.example.org.", "", false},
  {"[IPv6:::ffff:192.0.2.5]", "", false},
  {"[IPv6:fe80::1%eth0]", "", false},
  {"[IPv6:192.0.2.5]", "", false},
  {"[not-an-ip]", "", false},
  {"[2001:db8::5]", "", false},
  {"mail.example.org=evil", "", false},
  {"mail.example.org/evil", "", false},
  {"máil.example.org", "", false},
 }
 for _, tc := range cases {
  t.Run(tc.in, func(t *testing.T) {
   got, ok := parseSMTPXForwardHelo(tc.in)
   if got != tc.want || ok != tc.ok { t.Fatalf("got (%q,%v), want (%q,%v)", got,ok,tc.want,tc.ok) }
  })
 }
}

func TestParseSMTPXForwardHeloLengths(t *testing.T) {
 // A 63-byte label is valid, but 64 bytes is not.
 label := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
 if _, ok := parseSMTPXForwardHelo(label+".example"); !ok { t.Fatal("63-byte label rejected") }
 if _, ok := parseSMTPXForwardHelo(label+"a.example"); ok { t.Fatal("64-byte label accepted") }
}
