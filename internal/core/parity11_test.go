package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReputationByKindAndProviderResponses(t *testing.T) {
	for _, tc := range []struct {
		answer string
		listed bool
	}{
		{"127.0.0.2", true}, {"127.255.255.254", false}, {"127.0.0.1", false}, {"198.51.100.1", false},
	} {
		stub := &dnsblStub{ips: []net.IPAddr{{IP: net.ParseIP(tc.answer)}}}
		_, hit, err := domainDNSBLLookup(context.Background(), stub, "fedex.com", "rbl.example.test")
		if err != nil || hit != tc.listed || stub.called != "fedex.com.rbl.example.test" {
			t.Fatalf("reputation answer %q hit=%t err=%v q=%q", tc.answer, hit, err, stub.called)
		}
	}
	for _, bad := range []string{"127.0.0.1", "internal.local", "a..b", "https://phish.example", "-invalid.com", "127.0.0.1.evil/"} {
		r := &dnsblStub{}
		_, hit, err := domainDNSBLLookup(context.Background(), r, bad, "rbl.example.test")
		if hit || err != nil || r.called != "" {
			t.Errorf("query should have been skipped for %q", bad)
		}
	}
}
func TestPhishingVisibleLinkEvidenceAndFalsePositiveControls(t *testing.T) {
	for _, tc := range []struct {
		html string
		hits int
	}{
		{`<a href="https://attacker.test/login">https://fedex.com/tracking</a>`, 1},
		{`<a href="https://sub.fedex.com/track">https://fedex.com/track</a>`, 0},
		{`<a href="https://tracker.test/123">Track package</a>`, 0},
		{`<a href="mailto:a@example.org">https://fedex.com</a>`, 0},
	} {
		got := phishingVisibleLinks(tc.html)
		if len(got) != tc.hits {
			t.Errorf("%q => %v", tc.html, got)
		}
	}
	mime := "From: service@example.org\r\nTo: user@example.net\r\nSubject: Test\r\nDate: Tue, 27 Oct 2026 12:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n"
	raw := []byte(mime + base64.StdEncoding.EncodeToString([]byte(`<a href="https://bad.test">https://good.example.org</a>`)) + "\r\n")
	if got := detectPhishingLinks(raw); len(got) != 1 {
		t.Fatalf("encoded HTML not scanned: %+v", got)
	}
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateConfig(func(c *Config) error { c.Settings.PhishingLinks = true; return nil }); err != nil {
		t.Fatal(err)
	}
	scanner := &Scanner{Store: store, Resolver: stubDNS{}}
	mail, err := scanner.Scan(context.Background(), Input{Raw: raw, Sender: "service@example.org", Recipients: []string{"user@example.net"}, Connector: "milter"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range mail.Findings {
		if f.Symbol == "PHISHING_VISIBLE_LINK" && f.Score == 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing opt-in link evidence: %+v", mail.Findings)
	}
	if err = store.UpdateConfig(func(c *Config) error { c.Settings.PhishingLinks = false; return nil }); err != nil {
		t.Fatal(err)
	}
	next, err := scanner.Scan(context.Background(), Input{Raw: raw, Sender: "service@example.org", Recipients: []string{"user@example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range next.Findings {
		if f.Symbol == "PHISHING_VISIBLE_LINK" {
			t.Fatal("opt-out did not suppress link finding")
		}
	}
}
func TestPersistentGreylistAndRateLimitWithSafeDefaults(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := Message{Connector: "milter", ClientIP: "198.51.100.77", Sender: "sender@outer.example", Recipients: []string{"inbox@example.net"}, Action: "tag"}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	act, _, err := store.EvaluateDeliveryPolicy(m, now)
	if err != nil || act != "" {
		t.Fatalf("disabled by default act %q err %v", act, err)
	}
	if err = store.UpdateConfig(func(c *Config) error {
		c.Settings.GreylistEnabled = true
		c.Settings.GreylistWaitMinutes = 5
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	act, _, err = store.EvaluateDeliveryPolicy(m, now)
	if err != nil || act != "soft_reject" {
		t.Fatalf("initial must defer %q %v", act, err)
	}
	store, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	act, _, err = store.EvaluateDeliveryPolicy(m, now.Add(4*time.Minute))
	if err != nil || act != "soft_reject" {
		t.Fatalf("early retry must defer %q %v", act, err)
	}
	act, _, err = store.EvaluateDeliveryPolicy(m, now.Add(6*time.Minute))
	if err != nil || act != "" {
		t.Fatalf("later retry must pass %q %v", act, err)
	}
	m.ClientIP = "10.0.0.1"
	act, _, err = store.EvaluateDeliveryPolicy(m, now)
	if err != nil || act != "" {
		t.Fatalf("private source must be exempt %q %v", act, err)
	}
	m.ClientIP = "198.51.100.77"
	m.Action = "accept"
	if err = store.UpdateConfig(func(c *Config) error {
		c.Settings.GreylistEnabled = false
		c.Settings.RateLimitEnabled = true
		c.Settings.RateLimitPerHour = 10
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		act, _, err = store.EvaluateDeliveryPolicy(m, now.Add(time.Duration(i)*time.Second))
		if err != nil || act != "" {
			t.Fatalf("unexpected rate limit on %d: %q %v", i, act, err)
		}
	}
	act, _, err = store.EvaluateDeliveryPolicy(m, now.Add(11*time.Second))
	if err != nil || act != "soft_reject" {
		t.Fatalf("limit not applied: %q %v", act, err)
	}
	act, _, err = store.EvaluateDeliveryPolicy(m, now.Add(61*time.Minute))
	if err != nil || act != "" {
		t.Fatalf("limit did not reset: %q %v", act, err)
	}
	data := mustReadPolicy(t, dir)
	if bytes.Contains(data, []byte("sender@outer.example")) || bytes.Contains(data, []byte("198.51.100.77")) {
		t.Fatal("private identifiers leaked into gate state")
	}
}
func mustReadPolicy(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "delivery-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestMailReputationSourceProvenance(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateConfig(func(c *Config) error {
		c.Settings.DNSBLEnabled = true
		c.DNSLists = []DNSList{{Zone: "rbl.example.test", Kind: "domain", Enabled: true, Score: 3}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stub := &dnsblStub{ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.2")}}}
	raw := []byte("From: service@example.org\r\nTo: user@example.net\r\nSubject: Hi\r\nDate: Tue, 27 Oct 2026 12:00:00 +0000\r\n\r\nHello\r\n")
	scanner := &Scanner{Store: store, Resolver: stub}
	m, err := scanner.Scan(context.Background(), Input{Raw: raw, Sender: "sender@example.org", Recipients: []string{"user@example.net"}, ClientIP: "198.51.100.5", Connector: "milter"})
	if err != nil {
		t.Fatal(err)
	}
	matched := false
	for _, f := range m.Findings {
		if f.Source == "dnsbl/domain/rbl.example.test" && f.Score == 3 && strings.Contains(f.Detail, "example.org.rbl.example.test") {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("reputation did not retain zone and source: %+v", m.Findings)
	}
}
