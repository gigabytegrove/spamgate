package hostinspect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A custom command runner is used by offline inventory and tests. It must
// never make uninspected master.cf overrides appear safely enforced.
func TestUninspectedMasterCFNeverCertifiesCoverage(t *testing.T) {
	for _, tc := range []struct {
		name string
		inspect func(context.Context) (string, error)
		wantUncertain bool
		wantNote string
	}{
		{name: "skipped inspection", wantUncertain: true, wantNote: "were not inspected"},
		{name: "explicit clean inspection", inspect: func(context.Context) (string, error) {
			return "submission/inet/smtpd_tls_security_level=encrypt", nil
		}, wantUncertain: false},
		{name: "explicit bypass", inspect: func(context.Context) (string, error) {
			return "submission/inet/smtpd_milters=", nil
		}, wantUncertain: true, wantNote: "service-specific Milter overrides"},
		{name: "explicit inspection error", inspect: func(context.Context) (string, error) {
			return "", errors.New("permission denied")
		}, wantUncertain: true, wantNote: "Could not inspect Postfix master.cf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "etc/postfix/main.cf")
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, nil, 0644); err != nil {
				t.Fatal(err)
			}
			p := Probe{
				Root: root,
				Lookup: func(name string) (string, error) {
					if name == "postconf" { return "postconf", nil }
					return "", errors.New("not found")
				},
				Run: func(_ context.Context, _ string, args ...string) (string, error) {
					if len(args) != 2 || args[0] != "-h" {
						t.Fatalf("unexpected command arguments: %v", args)
					}
					switch args[1] {
					case "smtpd_milters", "non_smtpd_milters":
						return LocalMilter, nil
					case "milter_default_action":
						return "tempfail", nil
					case "milter_protocol":
						return "6", nil
					case "smtpd_milter_maps":
						return "", nil
					default:
						t.Fatalf("unexpected postconf key %q", args[1])
						return "", nil
					}
				},
				Reach: func(string) bool { return true },
				MasterOverrides: tc.inspect,
			}
			got := p.Detect(context.Background())
			if !got.PostfixConfigured || !got.MilterReady {
				t.Fatalf("fixture should have configured and reachable globals: %+v", got)
			}
			if got.PostfixCoverageUncertain != tc.wantUncertain {
				t.Fatalf("coverage uncertainty=%v, want %v: %+v", got.PostfixCoverageUncertain, tc.wantUncertain, got)
			}
			if tc.wantNote != "" && !strings.Contains(strings.Join(got.Notes, " | "), tc.wantNote) {
				t.Fatalf("expected note %q in %v", tc.wantNote, got.Notes)
			}
		})
	}
}
