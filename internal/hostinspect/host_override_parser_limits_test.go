package hostinspect

import (
	"strings"
	"testing"
)

func TestServiceOverrideParsingBoundsAndEvidence(t *testing.T) {
	tests := []struct {
		name string
		input string
		want []string
		truncated bool
	}{
		{
			name: "valid service and irrelevant parameter",
			input: "submission/inet/smtpd_milters = inet:127.0.0.1:38472\nsubmission/inet/cleanup_service_name = cleanup\n",
			want: []string{"submission/inet/smtpd_milters"},
		},
		{
			name: "malformed milter assignment",
			input: "submission/inet/smtpd_milters\n",
			truncated: true,
		},
		{
			name: "malformed service identity",
			input: "submission/smtpd_milters = disabled\n",
			truncated: true,
		},
		{
			name: "oversized untrusted line",
			input: strings.Repeat("x", 1024) + "\nsubmission/inet/smtpd_milters = value\n",
			want: []string{"submission/inet/smtpd_milters"},
			truncated: true,
		},
		{
			name: "large response bounded",
			input: "submission/inet/smtpd_milters = value\n" + strings.Repeat("x", 2<<20),
			want: []string{"submission/inet/smtpd_milters"},
			truncated: true,
		},
		{
			name: "duplicate identities",
			input: "submission/inet/smtpd_milters = first\nsubmission/inet/smtpd_milters = second\n",
			want: []string{"submission/inet/smtpd_milters"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, truncated := InspectMilterServiceOverrides(tt.input)
			if truncated != tt.truncated {
				t.Fatalf("truncated=%v, want %v", truncated, tt.truncated)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("identities=%q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("identity %d=%q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestServiceOverrideParserDoesNotLeakValues(t *testing.T) {
	secret := "sensitive-configuration-value"
	entries, truncated := InspectMilterServiceOverrides("submission/inet/smtpd_milters = " + secret)
	if truncated || len(entries) != 1 {
		t.Fatalf("unexpected result: %q truncated=%v", entries, truncated)
	}
	if strings.Contains(strings.Join(entries, ","), secret) {
		t.Fatal("configuration value leaked in diagnostic inventory")
	}
}
