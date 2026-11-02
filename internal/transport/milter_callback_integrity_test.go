package transport

import (
	"bytes"
	"testing"
)

func TestMilterClientAddressRequiresExactTerminatedIP(t *testing.T) {
	for _, tc := range []struct {
		name, packet, want string
	}{
		{"IPv4", "mx.example\x004\x00\x19" + "198.51.100.10\x00", "198.51.100.10"},
		{"IPv6", "mx.example\x006\x00\x19" + "2001:db8::2\x00", "2001:db8::2"},
		{"unterminated", "mx.example\x004\x00\x19" + "198.51.100.10", ""},
		{"trailing data", "mx.example\x004\x00\x19" + "198.51.100.10\x00extra", ""},
		{"second terminator", "mx.example\x004\x00\x19" + "198.51.100.10\x00extra\x00", ""},
		{"leading whitespace", "mx.example\x004\x00\x19" + " 198.51.100.10\x00", ""},
		{"missing address", "mx.example\x004\x00\x19\x00", ""},
		{"invalid IP", "mx.example\x004\x00\x19" + "example.org\x00", ""},
		{"non-IP family", "mx.example\x00U\x00\x19" + "198.51.100.10\x00", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := milterAddress([]byte(tc.packet)); got != tc.want {
				t.Fatalf("client IP %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMilterHeaderFieldNameRequiresRFC5322PrintableNoColon(t *testing.T) {
	for _, name := range []string{"Bad Name", "Bad:Name", "Bad\tName", "Bad\x7fName", "Bad\rName", "Bad\nName"} {
		if _, err := milterHeader([]byte(name+"\x00value\x00")); err == nil {
			t.Fatalf("accepted invalid header field name %q", name)
		}
	}
	for _, name := range []string{"X-SpamGate-ID", "DKIM-Signature", "List-Unsubscribe"} {
		got, err := milterHeader([]byte(name+"\x00value\x00"))
		if err != nil || !bytes.Equal(got, []byte(name+": value\r\n")) {
			t.Fatalf("rejected valid field name %q: %q, %v", name, got, err)
		}
	}
}
