package core

import (
	"context"
	"strings"
	"testing"
)

func TestRecipientEmailRulesCannotAffectUnrelatedSMTPRecipients(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	if err := store.UpdateConfig(func(c *Config) error {
		c.Rules = []Rule{
			{ID: "mailbox-block", Name: "Recipient-specific block", Kind: "recipient_email", Value: "alice@example.net", Score: 80, Action: "reject", Enabled: true, Priority: 900},
			{ID: "mailbox-score", Name: "Recipient-specific scoring", Kind: "recipient_email", Value: "alice@example.net", Score: 40, Enabled: true, Priority: 800},
		}
		return nil
	}); err != nil { t.Fatal(err) }
	scanner := &Scanner{Store: store, Resolver: stubDNS{}}
	raw := []byte("From: sender@example.org\r\nTo: alice@example.net, bob@example.net\r\nDate: Fri, 30 Oct 2026 12:00:00 +0000\r\nMessage-ID: <mixed@example.org>\r\nSubject: Ordinary notice\r\n\r\nHello.\r\n")
	cases := []struct {
		name string
		recipients []string
		wantReject bool
		wantSkipped bool
	}{
		{"single_target", []string{"alice@example.net"}, true, false},
		{"duplicate_target", []string{"alice@example.net", "ALICE@example.net"}, true, false},
		{"mixed_target_first", []string{"alice@example.net", "bob@example.net"}, false, true},
		{"mixed_target_last", []string{"bob@example.net", "alice@example.net"}, false, true},
		{"unrelated", []string{"bob@example.net"}, false, false},
		{"no_recipients", nil, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := scanner.Scan(context.Background(), Input{Raw: raw, Sender: "sender@example.org", Recipients: tc.recipients, Connector: "milter"})
			if err != nil { t.Fatal(err) }
			if (m.Action == "reject") != tc.wantReject { t.Fatalf("unexpected action %q for recipients %v: %+v", m.Action, tc.recipients, m.Findings) }
			if !tc.wantReject && m.Score >= 40 { t.Fatalf("mailbox-only score leaked to co-recipient: %f", m.Score) }
			var skipped bool
			for _, check := range m.Scoring.Checks {
				if check.Name == "Custom filtering rules" && strings.Contains(check.Detail, "skipped 2 recipient-specific") { skipped = true }
			}
			if skipped != tc.wantSkipped { t.Fatalf("missing or incorrect mixed-recipient trace: %+v", m.Scoring.Checks) }
		})
	}
}

func TestGlobalRuleStillAppliesToMixedRecipients(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	if err := store.UpdateConfig(func(c *Config) error {
		c.Rules = []Rule{{ID: "global-sender", Name: "Global sender block", Kind: "sender_email", Value: "blocked@example.org", Score: 40, Action: "reject", Enabled: true}}
		return nil
	}); err != nil { t.Fatal(err) }
	m, err := (&Scanner{Store: store, Resolver: stubDNS{}}).Scan(context.Background(), Input{
		Raw: []byte("From: blocked@example.org\r\nDate: Fri, 30 Oct 2026 12:00:00 +0000\r\nMessage-ID: <global@example.org>\r\n\r\nBody"),
		Sender: "blocked@example.org", Recipients: []string{"alice@example.net", "bob@example.net"}, Connector: "milter",
	})
	if err != nil { t.Fatal(err) }
	if m.Action != "reject" || m.Scoring.ForcedAction != "reject" { t.Fatalf("global policy was incorrectly suppressed: %+v", m) }
}
