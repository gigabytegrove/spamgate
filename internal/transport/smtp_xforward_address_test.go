package transport

import "testing"

func TestParseSMTPXForwardAddressStrict(t *testing.T) {
    cases := []struct{ value, expected string; ok bool }{
        {"192.0.2.12", "192.0.2.12", true},
        {"[192.0.2.12]", "192.0.2.12", true},
        {"2001:db8::12", "2001:db8::12", true},
        {"IPv6:2001:db8::12", "2001:db8::12", true},
        {"[IPv6:2001:db8::12]", "2001:db8::12", true},
        {"", "", false},
        {"[192.0.2.12", "", false},
        {"192.0.2.12]", "", false},
        {"[[192.0.2.12]]", "", false},
        {"IPv6:192.0.2.12", "", false},
        {"IPv6:IPv6:2001:db8::1", "", false},
        {"[IPv6:2001:db8::1]]", "", false},
        {"192.0.2.12\r", "", false},
        {"fe80::1%eth0", "", false},
        {"not-an-ip", "", false},
    }
    for _, tc := range cases {
        t.Run(tc.value, func(t *testing.T) {
            got, ok := parseSMTPXForwardAddress(tc.value)
            if ok != tc.ok || got != tc.expected {
                t.Fatalf("parse(%q)=(%q,%v), want (%q,%v)", tc.value, got, ok, tc.expected, tc.ok)
            }
        })
    }
}
