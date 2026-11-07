package hostinspect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestListMilterServiceOverrides(t *testing.T) {
	input := strings.Join([]string{
		"submission/inet/smtpd_milters=",
		"submission/inet/smtpd_milters=secret-value-not-for-report",
		"smtp/inet/milter_default_action=accept",
		"smtp/inet/my_smtpd_milters=none",
		"pickup/unix/non_smtpd_milters=",
		"malformed",
		"# smtp/inet/smtpd_milters=ignored",
		"bad/extra/path/smtpd_milters=",
	}, "\n")
	want := []string{
		"submission/inet/smtpd_milters",
		"smtp/inet/milter_default_action",
		"pickup/unix/non_smtpd_milters",
	}
	got := ListMilterServiceOverrides(input)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if strings.Contains(strings.Join(got, " "), "secret-value") {
		t.Fatal("diagnostic leaked a configuration value")
	}
	if !HasMilterServiceOverrides(input) || HasMilterServiceOverrides("submission/inet/smtpd_tls_security_level=encrypt") {
		t.Fatal("override detection inconsistent")
	}
}

func TestListMilterServiceOverridesBounded(t *testing.T) {
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, strings.Repeat("x", i+1)+"/inet/smtpd_milters=ignored")
	}
	got := ListMilterServiceOverrides(strings.Join(lines, "\n"))
	if len(got) != 64 { t.Fatalf("got %d entries, want 64", len(got)) }
	if entries := ListMilterServiceOverrides(strings.Repeat("x", 513)+"/inet/smtpd_milters=secret"); len(entries) != 0 {
		t.Fatalf("oversized identity was exposed: %v", entries)
	}
}

func TestPostfixReportIncludesOverrideIdentityWithoutValue(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc/postfix/main.cf")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, nil, 0644); err != nil { t.Fatal(err) }
	p := Probe{
		Root: root,
		Lookup: func(name string) (string, error) {
			if name == "postconf" { return "postconf", nil }
			return "", errors.New("missing")
		},
		Run: func(_ context.Context, _ string, args ...string) (string, error) {
			if len(args) != 2 || args[0] != "-h" { t.Fatalf("unexpected args: %v", args) }
			switch args[1] {
			case "smtpd_milters", "non_smtpd_milters": return LocalMilter, nil
			case "milter_default_action": return "tempfail", nil
			case "milter_protocol": return "6", nil
			case "smtpd_milter_maps": return "", nil
			}
			t.Fatalf("unexpected key: %v", args)
			return "", nil
		},
		Reach: func(string) bool { return true },
		MasterOverrides: func(context.Context) (string, error) {
			return "submission/inet/smtpd_milters=private-host-name", nil
		},
	}
	report := p.Detect(context.Background())
	if !report.PostfixCoverageUncertain { t.Fatal("service override must make coverage uncertain") }
	if !reflect.DeepEqual(report.PostfixServiceMilterOverrides, []string{"submission/inet/smtpd_milters"}) {
		t.Fatalf("incorrect diagnostic identities: %v", report.PostfixServiceMilterOverrides)
	}
}
