package core

import (
	"context"
	"strings"
	"testing"
)

func TestRFC9989TestModePolicyDowngrade(t *testing.T) {
	cases := []struct {
		policy string
		testing bool
		effective string
	}{
		{"reject", false, "reject"},
		{"reject", true, "quarantine"},
		{"quarantine", false, "quarantine"},
		{"quarantine", true, "none"},
		{"none", false, "none"},
		{"none", true, "none"},
	}
	for _, tc := range cases {
		got := effectiveDMARCPolicy(DMARCResult{Policy: tc.policy, Testing: tc.testing})
		if got != tc.effective { t.Fatalf("%s testing=%v got %s, want %s", tc.policy, tc.testing, got, tc.effective) }
	}
}

func TestRFC9989HistoricPctIgnoredAndMissingPDefaultsNone(t *testing.T) {
	cases := []struct {
		record, policy, result string
		testing bool
	}{
		{"v=DMARC1; p=reject; pct=0", "reject", "fail", false},
		{"v=DMARC1; p=reject; pct=not-a-percent", "reject", "fail", false},
		{"v=DMARC1; p=reject; pct=101", "reject", "fail", false},
		{"v=DMARC1; p=reject; t=y", "reject", "fail", true},
		{"v=DMARC1; p=reject; t=n", "reject", "fail", false},
		{"v=DMARC1; rua=mailto:reports@example.org", "none", "fail", false},
		{"v=dmarc1; p=reject", "", "none", false},
		{"p=reject; v=DMARC1", "", "none", false},
	}
	for _, tc := range cases {
		dns := stubDNS{txt: map[string][]string{"_dmarc.example.org": {tc.record}}}
		got := DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "fail"}, nil)
		if got.Result != tc.result || got.Policy != tc.policy || got.Testing != tc.testing {
			t.Fatalf("record %q got %+v, want result=%s policy=%s testing=%v", tc.record, got, tc.result, tc.policy, tc.testing)
		}
	}
}

func TestRFC9989TestModeScannerEvidenceAndScoring(t *testing.T) {
	raw := []byte("From: sender@example.org\r\nTo: alice@example.net\r\nDate: Sat, 31 Oct 2026 15:00:00 -0400\r\nMessage-ID: <test-mode@example.org>\r\nSubject: Normal message\r\n\r\nHello.")
	cases := []struct {
		name, record, effective, action string
		weight float64
	}{
		{"test reject", "v=DMARC1; p=reject; t=y", "quarantine", "tag", 4},
		{"normal reject", "v=DMARC1; p=reject; t=n", "reject", "reject", 6},
		{"historic pct ignored", "v=DMARC1; p=reject; pct=0", "reject", "reject", 6},
		{"test quarantine", "v=DMARC1; p=quarantine; t=y", "none", "accept", 0},
		{"normal quarantine", "v=DMARC1; p=quarantine", "quarantine", "tag", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, err := Open(t.TempDir())
			if err != nil { t.Fatal(err) }
			if err := store.UpdateConfig(func(c *Config) error {
				c.Settings.TagThreshold = 3
				c.Settings.QuarantineThreshold = 5
				c.Settings.RejectThreshold = 6
				return nil
			}); err != nil { t.Fatal(err) }
			dns := stubDNS{txt: map[string][]string{"_dmarc.example.org": {tc.record}}}
			m, err := (&Scanner{Store: store, Resolver: dns}).Scan(context.Background(), Input{
				Raw: raw, Sender: "sender@example.org", Recipients: []string{"alice@example.net"}, Connector: "test",
			})
			if err != nil { t.Fatal(err) }
			if m.Action != tc.action {
				t.Fatalf("action=%s want=%s score=%v findings=%+v", m.Action, tc.action, m.Score, m.Findings)
			}
			found := false
			for _, finding := range m.Findings {
				if finding.Symbol == "DMARC_FAIL" {
					found = true
					if finding.Score != tc.weight || !strings.Contains(finding.Detail, "effective scoring policy="+tc.effective) {
						t.Fatalf("incorrect DMARC evidence: %+v", finding)
					}
				}
			}
			if !found { t.Fatalf("missing DMARC_FAIL: %+v", m.Findings) }
		})
	}
}
