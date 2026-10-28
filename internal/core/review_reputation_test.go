package core

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestReviewedDomainReputationRequiresVerifiedReviewsAndDMARCPass(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		m := Message{ID: ID(), Timestamp: time.Now(), Sender: "sender@example.org", ReviewStatus: "not_spam", Action: "quarantine", Findings: []Finding{{Symbol: "DMARC_PASS", Source: "auth/dmarc/example.org", Score: -1}}}
		if err := store.Save(m); err != nil {
			t.Fatal(err)
		}
	}
	// An unauthenticated forged sender does not contribute to reputation.
	if err := store.Save(Message{ID: ID(), Timestamp: time.Now(), Sender: "sender@example.org", ReviewStatus: "spam", Action: "accept"}); err != nil {
		t.Fatal(err)
	}
	r := store.ReviewedDomainReputation("example.org")
	if !r.Ready || r.Weight != -1 || r.ConfirmedHam != 4 || r.ConfirmedSpam != 0 {
		t.Fatalf("bad reviewed reputation %+v", r)
	}
	if x := store.ReviewedDomainReputation("evil.example"); x.Ready || x.Weight != 0 {
		t.Fatal(x)
	}
	dns := stubDNS{txt: map[string][]string{"example.org": {"v=spf1 ip4:203.0.113.9 -all"}, "_dmarc.example.org": {"v=DMARC1; p=reject"}}}
	scanner := Scanner{Store: store, Resolver: dns}
	raw := []byte("From: sender@example.org\r\nDate: Tue, 27 Oct 2026 12:00:00 +0000\r\nTo: recipient@example.net\r\nSubject: Receipt\r\nMessage-ID: <reviewtest@example.org>\r\n\r\nHello\r\n")
	in := Input{Raw: raw, Sender: "sender@example.org", Recipients: []string{"recipient@example.net"}, ClientIP: net.ParseIP("203.0.113.9").String(), Connector: "milter"}
	scan, err := scanner.Scan(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range scan.Findings {
		if f.Symbol == "REVIEWED_DOMAIN_REPUTATION" {
			t.Fatal("disabled reputation added points")
		}
	}
	if err = store.UpdateConfig(func(c *Config) error { c.Settings.ReviewedReputation = true; return nil }); err != nil {
		t.Fatal(err)
	}
	scan, err = scanner.Scan(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range scan.Findings {
		if f.Symbol == "REVIEWED_DOMAIN_REPUTATION" && f.Score == -1 && f.Source == "learning/reviewed/example.org" {
			found = true
		}
	}
	if !found {
		t.Fatalf("review provenance was not recorded: %+v", scan.Findings)
	}
}
