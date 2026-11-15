package smtpprobe

import "testing"

func TestStartTLSEvidenceClassification(t *testing.T) {
	cases := []struct {
		name string
		lines []string
		warning string
	}{
		{"valid", []string{"mail.example", "STARTTLS", "SIZE 1024"}, ""},
		{"parameters", []string{"mail.example", "STARTTLS extra"}, "MALFORMED_STARTTLS_ADVERTISEMENT"},
		{"duplicate", []string{"mail.example", "STARTTLS", "STARTTLS"}, "DUPLICATE_STARTTLS_EXTENSION"},
		{"case duplicate", []string{"mail.example", "starttls", "STARTTLS"}, "DUPLICATE_STARTTLS_EXTENSION"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warnings := capabilityWarnings(tc.lines)
			if got := containsSMTPWarning(warnings, tc.warning); tc.warning != "" && !got {
				t.Fatalf("missing %s: %v", tc.warning, warnings)
			}
			advertised, _ := capabilities(tc.lines)
			if tc.warning == "" && !advertised {
				t.Fatal("valid STARTTLS advertisement was lost")
			}
			if tc.warning != "" {
				got := Assess(Result{BannerCode: 220, EHLOCode: 250, EHLOWarnings: warnings, StartTLSAdvertised: advertised})
				if !findingPresent(got, "STARTTLS_EVIDENCE_UNTRUSTWORTHY") {
					t.Fatalf("untrustworthy evidence not reported: %+v", got)
				}
				if findingPresent(got, "STARTTLS_NOT_ADVERTISED") {
					t.Fatalf("misleading missing capability finding: %+v", got)
				}
			}
		})
	}
}

func TestStartTLSAbsentIsDistinctFromMalformed(t *testing.T) {
	got := Assess(Result{BannerCode: 220, EHLOCode: 250})
	if !findingPresent(got, "STARTTLS_NOT_ADVERTISED") {
		t.Fatalf("missing STARTTLS finding: %+v", got)
	}
	if findingPresent(got, "STARTTLS_EVIDENCE_UNTRUSTWORTHY") {
		t.Fatalf("unexpected malformed finding: %+v", got)
	}
}
