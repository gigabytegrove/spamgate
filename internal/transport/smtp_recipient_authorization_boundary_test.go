package transport

import "testing"

// Authorization is a second security boundary even if the SMTP parser is
// bypassed by an internal caller or a future protocol adapter.
func TestSMTPRecipientAuthorizationRejectsMalformedEnvelopes(t *testing.T) {
	gateway := &SMTP{Domains: []string{"example.org", "k.example"}}
	cases := []struct {
		address string
		allowed bool
	}{
		{"Alice@EXAMPLE.ORG", true},
		{"Alice@example.org", true},
		{"Alice@K.EXAMPLE", true},
		{"Alice@k.example", true},
		{"Alice@example.org@EXAMPLE.ORG", false},
		{"@example.org", false},
		{"Alice@", false},
		{"Alice", false},
		{"Alice@K.example", false},
		{"Alice@Ｋ.example", false},
		{"Alice@example.org.", false},
		{"Alice@-example.org", false},
		{"Alice@example..org", false},
		{"Alice@example.org\r\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.address, func(t *testing.T) {
			if got := gateway.allowedRecipient(tc.address); got != tc.allowed {
				t.Fatalf("allowedRecipient(%q) = %v, want %v", tc.address, got, tc.allowed)
			}
		})
	}
}

func TestSMTPRecipientAuthorizationNeverUsesLastAtSign(t *testing.T) {
	gateway := &SMTP{Domains: []string{"example.org"}}
	for _, address := range []string{
		"attacker@unauthorized.invalid@example.org",
		"@example.org@example.org",
		"attacker@@example.org",
	} {
		if gateway.allowedRecipient(address) {
			t.Fatalf("malformed envelope authorized: %q", address)
		}
	}
}
