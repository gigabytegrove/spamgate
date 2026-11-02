package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDeliveryPolicyStateStrictPersistence(t *testing.T) {
	grey := stablePolicyKey("greylist", "198.51.100.5", "sender@example.org", "recipient@example.org")
	rate := stablePolicyKey("rate", "198.51.100.5")
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	good := deliveryPolicyState{
		Greylist: map[string]time.Time{grey: now},
		Rates: map[string][]time.Time{rate: {now, now.Add(time.Second)}},
	}
	goodBytes, err := json.Marshal(good)
	if err != nil { t.Fatal(err) }
	// Valid persisted counters must survive a cold startup without reset.
	dir := t.TempDir()
	path := filepath.Join(dir, "delivery-policy.json")
	if err := os.WriteFile(path, goodBytes, 0600); err != nil { t.Fatal(err) }
	s, err := Open(dir)
	if err != nil { t.Fatalf("valid persisted policy refused: %v", err) }
	if !s.policy.Greylist[grey].Equal(now) || len(s.policy.Rates[rate]) != 2 {
		t.Fatal("valid persisted enforcement counters were lost")
	}

	cases := map[string][]byte{
		"duplicate-root-key": []byte(`{"greylist":{},"rates":{},"rates":{}}`),
		"case-folded-root-alias": []byte(`{"greylist":{},"GREYLIST":{},"rates":{}}`),
		"unicode-escaped-root-alias": []byte(`{"greylist":{},"g\u0072eylist":{},"rates":{}}`),
		"unknown-root-field": []byte(`{"greylist":{},"rates":{},"reset":true}`),
		"malformed-utf8": append([]byte(`{"greylist":{},"rates":{},"x":"`), 0xff),
		"invalid-key": []byte(fmt.Sprintf(`{"greylist":{"not-a-digest":%q},"rates":{}}`, now.Format(time.RFC3339))),
		"invalid-time": []byte(fmt.Sprintf(`{"greylist":{"%s":"tomorrow"},"rates":{}}`, grey)),
		"zero-time": []byte(fmt.Sprintf(`{"greylist":{"%s":"0001-01-01T00:00:00Z"},"rates":{}}`, grey)),
		"null-rate-list": []byte(fmt.Sprintf(`{"greylist":{},"rates":{"%s":null}}`, rate)),
		"trailing-document": []byte(`{"greylist":{},"rates":{}} {"greylist":{}}`),
		"unpaired-surrogate": []byte(`{"greylist":{},"rates":{"\uD800":[]}}`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			file := filepath.Join(d, "delivery-policy.json")
			if err := os.WriteFile(file, raw, 0600); err != nil { t.Fatal(err) }
			if _, err := Open(d); err == nil { t.Fatal("ambiguous enforcement state accepted") }
			after, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(after, raw) { t.Fatal("rejected state was modified") }
		})
	}
}

func TestDeliveryPolicyStateRefusesOversizedAndSymlinkedFiles(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "delivery-policy.json")
		if err := os.WriteFile(path, nil, 0600); err != nil { t.Fatal(err) }
		if err := os.Truncate(path, maxDeliveryPolicyFileBytes+1); err != nil { t.Fatal(err) }
		if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "size limit") {
			t.Fatalf("oversized policy accepted: %v", err)
		}
	})
	if runtime.GOOS == "windows" { t.Skip("symlink permissions vary on Windows") }
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, []byte(`{"greylist":{},"rates":{}}`), 0600); err != nil { t.Fatal(err) }
		if err := os.Symlink(target, filepath.Join(dir, "delivery-policy.json")); err != nil { t.Fatal(err) }
		if _, err := Open(dir); err == nil { t.Fatal("symlinked policy evidence accepted") }
	})
}

func TestDeliveryPolicyCapacityRefusedBeforeCommit(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil { t.Fatal(err) }
	if err := s.UpdateConfig(func(c *Config) error {
		c.Settings.GreylistEnabled = true
		return nil
	}); err != nil { t.Fatal(err) }
	now := time.Now().UTC()
	for i := 0; i < maxDeliveryPolicyKeys; i++ {
		s.policy.Greylist[stablePolicyKey("greylist", fmt.Sprint(i))] = now
	}
	// All existing keys remain live, so a new triplet must be refused
	// rather than committing a 20,001st key to disk.
	m := Message{Connector: "milter", ClientIP: "198.51.100.5", Sender: "sender@example.org", Recipients: []string{"recipient@example.org"}, Action: "tag"}
	_, _, err = s.EvaluateDeliveryPolicy(m, now)
	if err == nil || !strings.Contains(err.Error(), "capacity") { t.Fatalf("capacity bypass: %v", err) }
	if len(s.policy.Greylist) != maxDeliveryPolicyKeys { t.Fatal("failed policy evaluation changed live counters") }
	if _, err := os.Stat(filepath.Join(dir, "delivery-policy.json")); !os.IsNotExist(err) {
		t.Fatalf("refused state was persisted: %v", err)
	}
}
