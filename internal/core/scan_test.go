package core

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPBKDF2Vector(t *testing.T) {
	got := pbkdf2([]byte("password"), []byte("salt"), 1, 32)
	if hex.EncodeToString(got) != "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" {
		t.Fatal("PBKDF2 mismatch")
	}
}
func TestScanRules(t *testing.T) {
	st, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	e = st.UpdateConfig(func(c *Config) error {
		c.Rules = append(c.Rules, Rule{ID: "custom1", Name: "Blocked domain", Kind: "sender_domain", Value: "bad.example", Score: 24, Enabled: true})
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	m, e := (&Scanner{Store: st}).Scan(context.Background(), Input{Raw: []byte("From: x@bad.example\r\nTo: alice@example.org\r\nDate: Sun, 25 Oct 2026 01:00:00 +0000\r\nMessage-ID: <abc@example.org>\r\nSubject: test\r\n\r\nHi"), Sender: "x@bad.example", Recipients: []string{"alice@example.org"}, Connector: "test"})
	if e != nil {
		t.Fatal(e)
	}
	if m.Action != "reject" || m.Score < 24 {
		t.Fatalf("unexpected result %+v", m)
	}
	if e = st.Save(m); e != nil {
		t.Fatal(e)
	}
	again, e := Open(st.dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := again.Get(m.ID); !ok {
		t.Fatal("message missing after reopen")
	}
}
func TestMIMEFindings(t *testing.T) {
	st, _ := Open(t.TempDir())
	raw := "From: a@b.com\r\nSubject: Verify your account\r\nMIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nAct immediately: https://192.0.2.3/login"
	m, e := (&Scanner{Store: st}).Scan(context.Background(), Input{Raw: []byte(raw)})
	if e != nil {
		t.Fatal(e)
	}
	if m.Score < 5 {
		t.Fatalf("expected score >=5, got %f", m.Score)
	}
	found := false
	for _, f := range m.Findings {
		if strings.Contains(f.Symbol, "IP_URL") {
			found = true
		}
	}
	if !found {
		t.Fatal("missing URL finding")
	}
}

func TestQuarantineRetentionDeletesExpiredOriginal(t *testing.T) {
	st, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	id := ID()
	if e := st.Quarantine(id, []byte("Subject: private\r\n\r\nsecret")); e != nil {
		t.Fatal(e)
	}
	if e := st.Save(Message{ID: id, Timestamp: time.Now().AddDate(0, 0, -40), Sender: "old@example.org", Delivery: "quarantined"}); e != nil {
		t.Fatal(e)
	}
	if _, ok := st.Get(id); ok {
		t.Fatal("expired message remained in history")
	}
	if _, e := st.Quarantined(id); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("expired quarantine original was not removed: %v", e)
	}
}

func TestBuiltinScoringPolicy(t *testing.T) {
	st, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	policy := SignalPolicy{Enabled: false, Score: 9}
	if e := st.UpdateConfig(func(c *Config) error {
		c.SignalPolicies["MISSING_DATE"] = policy
		c.SignalPolicies["CONTENT_VERIFY_YOUR_ACCOUNT"] = SignalPolicy{Enabled: true, Score: 17}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	raw := []byte("From: no-reply@example.net\r\nMessage-ID: <m@example.net>\r\nTo: alice@example.org\r\nSubject: verify your account\r\n\r\nMessage")
	// This test checks local signal-policy weights, not live DNS policy.
	// A public DMARC record for example.net must not change the expected score.
	m, e := (&Scanner{Store: st, Resolver: stubDNS{}}).Scan(context.Background(), Input{Raw: raw, Recipients: []string{"alice@example.org"}})
	if e != nil {
		t.Fatal(e)
	}
	seen := false
	for _, f := range m.Findings {
		if f.Symbol == "MISSING_DATE" {
			t.Fatal("disabled built-in detector contributed to scan")
		}
		if f.Symbol == "CONTENT_VERIFY_YOUR_ACCOUNT" {
			seen = true
			if f.Score != 17 {
				t.Fatalf("custom score not applied: %+v", f)
			}
		}
	}
	if !seen || m.Score != 17 || m.Action != "quarantine" {
		t.Fatalf("unexpected weighted scan: %+v", m)
	}
	opened, e := Open(st.dir)
	if e != nil {
		t.Fatal(e)
	}
	got := opened.Config().SignalPolicies["MISSING_DATE"]
	if got.Enabled || got.Score != 9 {
		t.Fatalf("signal policy not persisted: %+v", got)
	}
}
// A separate, deterministic regression test verifies that real DMARC policy
// evidence still influences scoring when the resolver supplies a reject policy.
// Do not disable DMARC in production to make the built-in policy test pass.
func TestBuiltinScoringPolicyWithDMARCReject(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateConfig(func(c *Config) error {
		c.SignalPolicies["MISSING_DATE"] = SignalPolicy{Enabled: false, Score: 9}
		c.SignalPolicies["CONTENT_VERIFY_YOUR_ACCOUNT"] = SignalPolicy{Enabled: true, Score: 17}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	resolver := stubDNS{txt: map[string][]string{
		"_dmarc.example.net": {"v=DMARC1; p=reject"},
	}}
	raw := []byte("From: no-reply@example.net\r\nMessage-ID: <m@example.net>\r\nTo: alice@example.org\r\nSubject: verify your account\r\n\r\nMessage")
	m, err := (&Scanner{Store: st, Resolver: resolver}).Scan(context.Background(), Input{Raw: raw, Recipients: []string{"alice@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	if m.Score != 23 || m.Action != "reject" {
		t.Fatalf("expected 17 content + 6 DMARC and reject, got score=%v action=%q", m.Score, m.Action)
	}
	var found bool
	for _, f := range m.Findings {
		if f.Symbol == "DMARC_FAIL" {
			found = true
			if f.Score != 6 {
				t.Fatalf("expected DMARC reject penalty 6, got %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("expected DMARC_FAIL finding, got %+v", m.Findings)
	}
}
