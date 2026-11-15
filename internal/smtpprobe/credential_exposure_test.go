package smtpprobe

import "testing"

func hasCredentialExposure(r Result) bool {
	for _, f := range Assess(r) {
		if f.Code == "CLEARTEXT_CREDENTIAL_AUTH_ADVERTISED" {
			return true
		}
	}
	return false
}

func TestCredentialExposureEvidence(t *testing.T) {
	cases := []struct {
		name string
		result Result
		want bool
	}{
		{"plain pre TLS", Result{EHLOCode: 250, AuthMechanisms: []string{"PLAIN"}}, true},
		{"login pre TLS with STARTTLS", Result{EHLOCode: 250, StartTLSAdvertised: true, AuthMechanisms: []string{"LOGIN"}}, true},
		{"scram pre TLS", Result{EHLOCode: 250, AuthMechanisms: []string{"SCRAM-SHA-256"}}, false},
		{"only after TLS", Result{EHLOCode: 250, StartTLSVerified: true, PostTLSEHLOCode: 250, PostTLSAuthMechanisms: []string{"PLAIN"}}, false},
		{"ambiguous AUTH", Result{EHLOCode: 250, AuthMechanisms: []string{"PLAIN"}, EHLOWarnings: []string{"DUPLICATE_AUTH_EXTENSION"}}, false},
		{"no successful EHLO", Result{EHLOCode: 550, AuthMechanisms: []string{"PLAIN"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasCredentialExposure(tc.result); got != tc.want {
				t.Fatalf("credential exposure finding = %v, want %v", got, tc.want)
			}
		})
	}
}
