package core

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

func TestDMARCPolicySamplingRFC7489Downgrade(t *testing.T) {
	cases := []struct {
		name, published, effective string
		percent, draw int
		selected bool
	}{
		{"full reject", "reject", "reject", 100, 99, true},
		{"zero reject", "reject", "quarantine", 0, 0, false},
		{"selected reject", "reject", "reject", 20, 19, true},
		{"unselected reject", "reject", "quarantine", 20, 20, false},
		{"zero quarantine", "quarantine", "none", 0, 0, false},
		{"selected quarantine", "quarantine", "quarantine", 20, 0, true},
		{"unselected quarantine", "quarantine", "none", 20, 99, false},
		{"none stays none", "none", "none", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, selected := dmarcPolicyAtSample(tc.published, tc.percent, tc.draw)
			if got != tc.effective || selected != tc.selected {
				t.Fatalf("got %s/%v, want %s/%v", got, selected, tc.effective, tc.selected)
			}
		})
	}
}

func TestDMARCPolicyPercentPreservesAuthenticationEvidence(t *testing.T) {
	cases := []struct {
		record string
		percent int
		result string
	}{
		{"v=DMARC1; p=reject", 100, "fail"},
		{"v=DMARC1; p=reject; pct=0", 0, "fail"},
		{"v=DMARC1; p=quarantine; pct=025", 25, "fail"},
		{"v=DMARC1; p=none; pct=100", 100, "fail"},
		{"v=DMARC1; p=reject; pct=0000", 0, "permerror"},
	}
	for _, tc := range cases {
		dns := stubDNS{txt: map[string][]string{"_dmarc.example.org": {tc.record}}}
		got := DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "fail"}, nil)
		if got.Result != tc.result {
			t.Fatalf("record %q returned %+v, want %s", tc.record, got, tc.result)
		}
		if got.Result == "fail" && (got.Percent != tc.percent || got.Policy == "") {
			t.Fatalf("lost policy percentage: %+v", got)
		}
	}
}

func TestDMARCPctScannerEvidenceAndScoring(t *testing.T) {
	raw := []byte("From: sender@example.org\r\nTo: alice@example.net\r\nDate: Sat, 31 Oct 2026 15:00:00 -0400\r\nMessage-ID: <pct-test@example.org>\r\nSubject: Normal message\r\n\r\nHello.")
	cases := []struct {
		name, policy string
		percent int
		weight float64
		action string
	}{
		{"reject sampled out", "reject", 0, 4, "tag"},
		{"reject selected", "reject", 100, 6, "reject"},
		{"quarantine sampled out", "quarantine", 0, 0, "accept"},
		{"quarantine selected", "quarantine", 100, 4, "tag"},
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
			dns := stubDNS{txt: map[string][]string{
				"_dmarc.example.org": {"v=DMARC1; p=" + tc.policy + "; pct=" + strconv.Itoa(tc.percent)},
			}}
			m, err := (&Scanner{Store: store, Resolver: dns}).Scan(context.Background(), Input{
				Raw: raw, Sender: "sender@example.org", Recipients: []string{"alice@example.net"}, Connector: "test",
			})
			if err != nil { t.Fatal(err) }
			if m.Action != tc.action {
				t.Fatalf("action=%q want=%q score=%v findings=%+v", m.Action, tc.action, m.Score, m.Findings)
			}
			found := false
			for _, finding := range m.Findings {
				if finding.Symbol == "DMARC_FAIL" {
					found = true
					if finding.Score != tc.weight || !strings.Contains(finding.Detail, "pct="+strconv.Itoa(tc.percent)) {
						t.Fatalf("incorrect DMARC evidence: %+v", finding)
					}
				}
			}
			if !found { t.Fatalf("missing DMARC_FAIL: %+v", m.Findings) }
		})
	}
}

func TestDMARCChoosePolicyRejectsInvalidPercent(t *testing.T) {
	for _, pct := range []int{-1, 101} {
		if _, _, err := chooseDMARCPolicy(DMARCResult{Result: "fail", Policy: "reject", Percent: pct}); err == nil {
			t.Fatalf("expected invalid percentage error for %d", pct)
		}
	}
}
