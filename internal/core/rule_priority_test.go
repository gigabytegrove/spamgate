package core

import (
	"context"
	"testing"
	"time"
)

func TestRulePriorityAndExpiration(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	err = store.UpdateConfig(func(c *Config) error {
		c.Rules = []Rule{
			{ID: "low", Name: "Low override", Kind: "sender_email", Value: "sender@localhost", Action: "accept", Enabled: true, Priority: 0},
			{ID: "high", Name: "High override", Kind: "sender_email", Value: "sender@localhost", Action: "reject", Enabled: true, Priority: 300},
			{ID: "old", Name: "Expired override", Kind: "sender_email", Value: "sender@localhost", Action: "quarantine", Enabled: true, Priority: 900, ExpiresAt: time.Now().Add(-time.Hour)},
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: sender@localhost\r\nTo: user@localhost\r\nSubject: hello\r\n\r\nHello\r\n")
	m, err := (&Scanner{Store: store}).Scan(context.Background(), Input{Raw: raw, Sender: "sender@localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Action != "reject" {
		t.Fatalf("priority violation: %s", m.Action)
	}
}
