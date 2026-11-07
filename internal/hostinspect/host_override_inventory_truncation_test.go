package hostinspect

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestInspectMilterServiceOverridesTruncation(t *testing.T) {
    var entries []string
    for i := 0; i < 65; i++ {
        entries = append(entries, fmt.Sprintf("submission%d/inet/smtpd_milters=secret%d", i, i))
    }
    cases := []struct {
        name string
        input string
        wantCount int
        truncated bool
    }{
        {"empty", "", 0, false},
        {"unrelated", "submission/inet/syslog_name=postfix", 0, false},
        {"exact limit", strings.Join(entries[:64], "\n"), 64, false},
        {"over limit", strings.Join(entries, "\n"), 64, true},
        {"oversized candidate", strings.Repeat("x", 513)+"/inet/smtpd_milters=secret", 0, true},
        {"oversized unrelated", strings.Repeat("x", 513)+"/inet/syslog_name=secret", 0, false},
        {"duplicate", strings.Join([]string{entries[0], entries[0]}, "\n"), 1, false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            got, truncated := InspectMilterServiceOverrides(tc.input)
            if len(got) != tc.wantCount || truncated != tc.truncated {
                t.Fatalf("count=%d truncated=%v; want count=%d truncated=%v", len(got), truncated, tc.wantCount, tc.truncated)
            }
            for _, key := range got {
                if strings.Contains(key, "secret") || strings.Contains(key, "=") {
                    t.Fatalf("configuration value exposed: %q", key)
                }
            }
        })
    }
}

func TestPostfixTruncatedServiceInventoryFailsClosed(t *testing.T) {
    root := t.TempDir()
    path := filepath.Join(root, "etc/postfix/main.cf")
    if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil { t.Fatal(err) }
    if err := os.WriteFile(path, nil, 0644); err != nil { t.Fatal(err) }
    var entries []string
    for i := 0; i < 65; i++ {
        entries = append(entries, fmt.Sprintf("submission%d/inet/smtpd_milters=secret", i))
    }
    probe := Probe{
        Root: root,
        Lookup: func(name string) (string, error) {
            if name == "postconf" { return "postconf", nil }
            return "", errors.New("not found")
        },
        Reach: func(string) bool { return true },
        Run: func(_ context.Context, _ string, args ...string) (string, error) {
            if len(args) != 2 || args[0] != "-h" { t.Fatalf("unexpected command: %v", args) }
            switch args[1] {
            case "smtpd_milters", "non_smtpd_milters": return LocalMilter, nil
            case "milter_default_action": return "tempfail", nil
            case "milter_protocol": return "6", nil
            case "smtpd_milter_maps": return "", nil
            }
            t.Fatalf("unexpected parameter: %v", args)
            return "", nil
        },
        MasterOverrides: func(context.Context) (string, error) { return strings.Join(entries, "\n"), nil },
    }
    report := probe.Detect(context.Background())
    if !report.PostfixCoverageUncertain || !report.PostfixServiceOverrideInventoryTruncated {
        t.Fatalf("truncated inventory incorrectly trusted: %+v", report)
    }
    if len(report.PostfixServiceMilterOverrides) != 64 {
        t.Fatalf("inventory count=%d; want 64", len(report.PostfixServiceMilterOverrides))
    }
    if !strings.Contains(strings.Join(report.Notes, " "), "inventory is incomplete") {
        t.Fatalf("missing incomplete inventory warning: %v", report.Notes)
    }
}
