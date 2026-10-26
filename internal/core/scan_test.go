package core

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
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
