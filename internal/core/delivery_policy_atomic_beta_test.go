package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Persistence failures must not consume rate allowances or mutate in-memory
// greylist state. A directory at the policy filename makes rename fail even
// when CI runs as root, without relying on permission-bit behavior.
func TestDeliveryPolicyFailurePreservesInMemoryState(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil { t.Fatal(err) }
	if err := store.UpdateConfig(func(c *Config) error {
		c.Settings.GreylistEnabled = true
		c.Settings.GreylistWaitMinutes = 5
		c.Settings.RateLimitEnabled = true
		c.Settings.RateLimitPerHour = 2
		return nil
	}); err != nil { t.Fatal(err) }
	now := time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC)
	grey := stablePolicyKey("greylist", "198.51.100.10", "old@example.org", "a@example.net")
	rate := stablePolicyKey("rate", "198.51.100.10")
	old := now.Add(-48 * time.Hour)
	store.policy.Greylist[grey] = old
	store.policy.Rates[rate] = []time.Time{now.Add(-2 * time.Hour)}
	policyFile := filepath.Join(dir, "delivery-policy.json")
	if err := os.Mkdir(policyFile, 0700); err != nil { t.Fatal(err) }
	m := Message{Connector: "milter", ClientIP: "198.51.100.10", Sender: "new@example.org", Recipients: []string{"a@example.net"}, Action: "tag"}
	if _, _, err := store.EvaluateDeliveryPolicy(m, now); err == nil {
		t.Fatal("expected persistence failure")
	}
	if got := store.policy.Greylist[grey]; !got.Equal(old) {
		t.Fatalf("failed persistence expired live greylist entry: %v", got)
	}
	if got := store.policy.Rates[rate]; len(got) != 1 || !got[0].Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("failed persistence mutated live rate state: %v", got)
	}
	if err := os.Remove(policyFile); err != nil { t.Fatal(err) }
	action, _, err := store.EvaluateDeliveryPolicy(m, now)
	if err != nil || action != "soft_reject" { t.Fatalf("recovery failed: %q %v", action, err) }
	if _, ok := store.policy.Greylist[grey]; ok { t.Fatal("expired greylist entry survived successful commit") }
	if got := store.policy.Rates[rate]; len(got) != 1 || !got[0].Equal(now) {
		t.Fatalf("rate state not correctly pruned and committed: %v", got)
	}
	reopened, err := Open(dir)
	if err != nil { t.Fatal(err) }
	if len(reopened.policy.Greylist) != len(store.policy.Greylist) || len(reopened.policy.Rates[rate]) != 1 {
		t.Fatalf("on-disk policy differs from committed memory: %+v", reopened.policy)
	}
}

func TestDeliveryPolicyPersistenceFailureDoesNotConsumeAllowance(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil { t.Fatal(err) }
	if err := store.UpdateConfig(func(c *Config) error {
		c.Settings.RateLimitEnabled = true
		c.Settings.RateLimitPerHour = 1
		return nil
	}); err != nil { t.Fatal(err) }
	now := time.Date(2026, 10, 30, 3, 0, 0, 0, time.UTC)
	m := Message{Connector: "milter", ClientIP: "198.51.100.11", Sender: "sender@example.org", Recipients: []string{"a@example.net"}, Action: "accept"}
	path := filepath.Join(dir, "delivery-policy.json")
	if err := os.Mkdir(path, 0700); err != nil { t.Fatal(err) }
	if _, _, err := store.EvaluateDeliveryPolicy(m, now); err == nil { t.Fatal("expected failed state write") }
	if len(store.policy.Rates) != 0 { t.Fatalf("failed write consumed allowance: %+v", store.policy.Rates) }
	if err := os.Remove(path); err != nil { t.Fatal(err) }
	if action, _, err := store.EvaluateDeliveryPolicy(m, now); err != nil || action != "" {
		t.Fatalf("first accepted request after recovery should be allowed: %q %v", action, err)
	}
	if action, _, err := store.EvaluateDeliveryPolicy(m, now.Add(time.Second)); err != nil || action != "soft_reject" {
		t.Fatalf("second request must be rate-limited: %q %v", action, err)
	}
}
