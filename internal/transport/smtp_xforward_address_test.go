package transport

import "testing"

func TestParseSMTPXForwardAddressStrict(t *testing.T) {
	cases := []struct {
		input, want string
		valid       bool
	}{
		{"192.0.2.12", "192.0.2.12", true},
		{"[192.0.2.12]", "192.0.2.12", true},
		{"2001:db8::12", "2001:db8::12", true},
		{"IPv6:2001:db8::12", "2001:db8::12", true},
		{"[IPv6:2001:0db8::0012]", "2001:db8::12", true},
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
		{"::ffff:192.0.2.12", "", false},
		{"IPv6:::ffff:192.0.2.12", "", false},
		{"[IPv6:::ffff:192.0.2.12]", "", false},
		{"[::ffff:c000:20c]", "", false},
		{"192.0.2.012", "", false},
		{"192.0.2.12 ", "", false},
		{" 192.0.2.12", "", false},
		{"2001:db8::1%eth0", "", false},
		{"IPv6:2001:db8::1%eth0", "", false},
		{"192.0.2.12\t", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := parseSMTPXForwardAddress(tc.input)
			if got != tc.want || ok != tc.valid {
				t.Fatalf("parse(%q) = (%q,%v), want (%q,%v)", tc.input, got, ok, tc.want, tc.valid)
			}
		})
	}
}
