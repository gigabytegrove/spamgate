package core

import "testing"

func TestPhishingBrowserIPv4(t *testing.T) {
 cases := []struct { host, want string }{
  {"134744072", "8.8.8.8"},
  {"0x08080808", "8.8.8.8"},
  {"010.010.010.010", "8.8.8.8"},
  {"8.8.2056", "8.8.8.8"},
  {"8.526344", "8.8.8.8"},
  {"8.8.8.8.", "8.8.8.8"},
  {"0x7f000001", "127.0.0.1"},
  {"0300.0250.01.01", "192.168.1.1"},
  {"2130706433", "127.0.0.1"},
  {"0x", ""}, {"08.8.8.8", ""},
  {"4294967296", ""}, {"256.1.1.1", ""},
  {"1.2.3.65536", ""}, {"1.2.3.4.5", ""},
  {"1..2", ""}, {"-1", ""}, {"+8", ""},
  {"example.com", ""}, {"", ""},
 }
 for _, tc := range cases {
  t.Run(tc.host, func(t *testing.T) {
   got, ok := phishingBrowserIPv4(tc.host)
   if tc.want == "" {
    if ok { t.Fatalf("unexpected address %v", got) }
   } else if !ok || got.String() != tc.want {
    t.Fatalf("got %v valid=%v; want %s", got, ok, tc.want)
   }
  })
 }
}

func TestPhishingBrowserNumericDestinationPolicy(t *testing.T) {
 for _, tc := range []struct{ host string; want bool }{
  {"134744072", true}, {"0x08080808", true},
  {"010.010.010.010", true}, {"8.8.2056", true},
  {"0x7f000001", false}, {"2130706433", false},
  {"0300.0250.01.01", false}, {"0xc0000201", false},
  {"0x64400001", false}, {"0xcb007101", false},
  {"4294967296", false}, {"08.8.8.8", false},
 } {
  if got := phishingPublicDestinationHost(tc.host); got != tc.want {
   t.Errorf("host %q: got %v want %v", tc.host, got, tc.want)
  }
 }
}

func TestPhishingBrowserNumericEndToEnd(t *testing.T) {
 for _, tc := range []struct { host string; want int }{
  {"134744072", 1}, {"0x08080808", 1}, {"8.8.2056", 1},
  {"0x7f000001", 0}, {"0300.0250.01.01", 0},
  {"0xc0000201", 0}, {"0xcb007101", 0},
 } {
  raw := phishingFixture("text/html", "", "", `<a href="https://`+tc.host+`/login">https://bank.example.com/login</a>`)
  got, coverage := detectPhishingLinksWithCoverage(raw)
  if coverage.Incomplete || len(got) != tc.want {
   t.Errorf("host %q: findings=%v coverage=%+v want=%d", tc.host, got, coverage, tc.want)
  }
 }
}
