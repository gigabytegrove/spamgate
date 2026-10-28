package core

import (
	"context"
	"encoding/json"
	"math"
	"testing"
)

func TestScoringTracePersistsAndCapturesPolicyAtScanTime(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateConfig(func(c *Config) error {
		c.Settings.TagThreshold = 3
		c.Settings.QuarantineThreshold = 8
		c.Settings.RejectThreshold = 21
		c.Rules = append(c.Rules, Rule{ID: "trusted", Name: "Score known sender", Kind: "sender_email", Value: "sender@sender.example", Score: -2.5, Enabled: true})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: sender@sender.example\r\nTo: me@example.org\r\nDate: Tue, 27 Oct 2026 10:00:00 -0400\r\nMessage-ID: <trace@example.org>\r\nSubject: verify your account\r\n\r\nPlease verify your account.")
	m, err := (&Scanner{Store: st}).Scan(context.Background(), Input{Raw: raw, Sender: "sender@sender.example", Recipients: []string{"me@example.org"}, Connector: "milter"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Scoring == nil || m.Scoring.TagThreshold != 3 || m.Scoring.QuarantineThreshold != 8 || m.Scoring.RejectThreshold != 21 {
		t.Fatalf("incorrect snapshot: %+v", m.Scoring)
	}
	if len(m.Scoring.Checks) < 10 {
		t.Fatalf("missing scan coverage: %+v", m.Scoring.Checks)
	}
	seenSkipped := false
	seenMatch := false
	for _, c := range m.Scoring.Checks {
		if c.Status == "skipped" {
			seenSkipped = true
		}
		if c.Status == "match" {
			seenMatch = true
		}
	}
	if !seenSkipped || !seenMatch {
		t.Fatalf("missing skipped/matched status: %+v", m.Scoring.Checks)
	}
	sum := 0.0
	for _, f := range m.Findings {
		sum += f.Score
	}
	if math.Abs(m.Score-sum) > 0.01 {
		t.Fatalf("stored sum %.2f != %.2f", m.Score, sum)
	}
	if err = st.Save(m); err != nil {
		t.Fatal(err)
	}
	if err = st.UpdateConfig(func(c *Config) error { c.Settings.TagThreshold = 4; return nil }); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(st.dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Get(m.ID)
	if !ok || got.Scoring == nil || got.Scoring.TagThreshold != 3 {
		t.Fatalf("historical thresholds rewritten: %+v", got.Scoring)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Message
	if err = json.Unmarshal(b, &roundtrip); err != nil || roundtrip.Scoring == nil {
		t.Fatalf("invalid trace json: %v", err)
	}
}

func TestLegacyMessageScoringTraceOptional(t *testing.T) {
	var m Message
	if err := json.Unmarshal([]byte(`{"id":"abc","score":4,"findings":[{"symbol":"test","score":4}]}`), &m); err != nil {
		t.Fatal(err)
	}
	if m.Scoring != nil || m.Score != 4 {
		t.Fatalf("legacy history must still decode: %+v", m)
	}
}
