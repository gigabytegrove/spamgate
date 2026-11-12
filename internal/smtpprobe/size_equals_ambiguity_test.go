package smtpprobe

import "testing"

func TestSizeEvidenceMalformedEqualsAdvertisement(t *testing.T) {
	cases := []struct {
		name string
		lines []string
		advertised, known bool
		limit uint64
		warning string
	}{
		{"equals alone", []string{"mail.example", "SIZE=100"}, true, false, 0, "MALFORMED_SIZE_ADVERTISEMENT"},
		{"equals empty", []string{"mail.example", "SIZE="}, true, false, 0, "MALFORMED_SIZE_ADVERTISEMENT"},
		{"equals before valid", []string{"mail.example", "SIZE=100", "SIZE 200"}, true, false, 0, "DUPLICATE_SIZE_ADVERTISEMENT"},
		{"equals after valid", []string{"mail.example", "SIZE 200", "SIZE=100"}, true, false, 0, "DUPLICATE_SIZE_ADVERTISEMENT"},
		{"equals case insensitive", []string{"mail.example", "size=100"}, true, false, 0, "MALFORMED_SIZE_ADVERTISEMENT"},
		{"identity not extension", []string{"SIZE=100", "PIPELINING"}, false, false, 0, ""},
		{"unrelated keyword", []string{"mail.example", "SIZEX=100"}, false, false, 0, ""},
		{"valid remains valid", []string{"mail.example", "SIZE 200"}, true, true, 200, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			advertised, known, limit, warning := sizeEvidence(tc.lines)
			if advertised != tc.advertised || known != tc.known || limit != tc.limit || warning != tc.warning {
				t.Fatalf("sizeEvidence = (%t,%t,%d,%q), want (%t,%t,%d,%q)", advertised, known, limit, warning, tc.advertised, tc.known, tc.limit, tc.warning)
			}
		})
	}
}
