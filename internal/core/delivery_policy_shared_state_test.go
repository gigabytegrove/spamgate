package core

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func policyTestStore(t *testing.T, dir string, limit int) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil { t.Fatal(err) }
	if err := s.UpdateConfig(func(c *Config) error {
		c.Settings.RateLimitEnabled = true
		c.Settings.RateLimitPerHour = limit
		return nil
	}); err != nil { t.Fatal(err) }
	return s
}

func TestDeliveryPolicyTwoStoresShareRateLimit(t *testing.T) {
	dir := t.TempDir()
	a := policyTestStore(t, dir, 10)
	b := policyTestStore(t, dir, 10)
	now := time.Date(2026, 11, 2, 15, 0, 0, 0, time.UTC)
	m := Message{Connector:"milter", ClientIP:"198.51.100.31", Action:"accept"}
	for i := 0; i < 10; i++ {
		if action, _, err := a.EvaluateDeliveryPolicy(m, now.Add(time.Duration(i)*time.Second)); err != nil || action != "" {
			t.Fatalf("request %d: %q %v", i+1, action, err)
		}
	}
	if action, _, err := b.EvaluateDeliveryPolicy(m, now.Add(10*time.Second)); err != nil || action != "soft_reject" {
		t.Fatalf("stale second store bypassed rate limit: %q %v", action, err)
	}
	if got := len(b.policy.Rates[stablePolicyKey("rate", "198.51.100.31")]); got != 10 {
		t.Fatalf("second store lost first counters: %d", got)
	}
}

func TestDeliveryPolicyConcurrentStoresDoNotLoseCounters(t *testing.T) {
	if runtime.GOOS != "linux" { t.Skip("cross-process advisory lock is native Linux only") }
	dir := t.TempDir()
	a := policyTestStore(t, dir, 10)
	b := policyTestStore(t, dir, 10)
	m := Message{Connector:"milter", ClientIP:"198.51.100.32", Action:"accept"}
	now := time.Date(2026, 11, 2, 15, 0, 0, 0, time.UTC)
	const attempts = 16
	var wg sync.WaitGroup
	actions := make(chan string, attempts)
	errs := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 == 1 { s = b }
			action, _, err := s.EvaluateDeliveryPolicy(m, now)
			actions <- action
			if err != nil { errs <- err }
		}(i)
	}
	wg.Wait()
	close(actions)
	close(errs)
	for err := range errs { t.Errorf("policy evaluation: %v", err) }
	allowed, refused := 0, 0
	for action := range actions {
		switch action {
		case "": allowed++
		case "soft_reject": refused++
		default: t.Errorf("unexpected action: %q", action)
		}
	}
	if allowed != 10 || refused != attempts-10 {
		t.Fatalf("lost or duplicated allowance: accepted=%d refused=%d", allowed, refused)
	}
	reopened, err := Open(dir)
	if err != nil { t.Fatal(err) }
	if got := len(reopened.policy.Rates[stablePolicyKey("rate", m.ClientIP)]); got != 10 {
		t.Fatalf("durable count=%d, want 10", got)
	}
}

func TestDeliveryPolicyRejectsChangedEvidenceAfterStartup(t *testing.T) {
	dir := t.TempDir()
	s := policyTestStore(t, dir, 10)
	now := time.Date(2026, 11, 2, 15, 0, 0, 0, time.UTC)
	m := Message{Connector:"milter", ClientIP:"198.51.100.33", Action:"accept"}
	if _, _, err := s.EvaluateDeliveryPolicy(m, now); err != nil { t.Fatal(err) }
	path := filepath.Join(dir, "delivery-policy.json")
	corrupt := []byte(`{"greylist":{},"rates":{},"rates":{}}`)
	if err := os.WriteFile(path, corrupt, 0600); err != nil { t.Fatal(err) }
	if _, _, err := s.EvaluateDeliveryPolicy(m, now.Add(time.Second)); err == nil {
		t.Fatal("running worker accepted corrupted enforcement state")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, corrupt) { t.Fatal("corrupt forensic evidence was overwritten") }
	if got := len(s.policy.Rates[stablePolicyKey("rate", m.ClientIP)]); got != 1 {
		t.Fatalf("failed refresh mutated live state: %d", got)
	}
}

func TestDeliveryPolicyRefusesMissingPreviouslyPublishedState(t *testing.T) {
	dir := t.TempDir()
	s := policyTestStore(t, dir, 10)
	now := time.Date(2026, 11, 2, 15, 0, 0, 0, time.UTC)
	m := Message{Connector:"milter", ClientIP:"198.51.100.34", Action:"accept"}
	if _, _, err := s.EvaluateDeliveryPolicy(m, now); err != nil { t.Fatal(err) }
	path := filepath.Join(dir, "delivery-policy.json")
	if err := os.Remove(path); err != nil { t.Fatal(err) }
	if _, _, err := s.EvaluateDeliveryPolicy(m, now.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("silently reset deleted counters: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) { t.Fatalf("deleted state recreated: %v", err) }
}

func TestDeliveryPolicyReloadsValidExternalState(t *testing.T) {
	dir := t.TempDir()
	a := policyTestStore(t, dir, 10)
	b := policyTestStore(t, dir, 10)
	now := time.Date(2026, 11, 2, 15, 0, 0, 0, time.UTC)
	m := Message{Connector:"milter", ClientIP:"198.51.100.35", Action:"accept"}
	if _, _, err := a.EvaluateDeliveryPolicy(m, now); err != nil { t.Fatal(err) }
	if _, _, err := b.EvaluateDeliveryPolicy(m, now.Add(time.Second)); err != nil { t.Fatal(err) }
	for i := 2; i < 10; i++ {
		if _, _, err := b.EvaluateDeliveryPolicy(m, now.Add(time.Duration(i)*time.Second)); err != nil { t.Fatal(err) }
	}
	raw, err := os.ReadFile(filepath.Join(dir, "delivery-policy.json"))
	if err != nil { t.Fatal(err) }
	var state deliveryPolicyState
	if err := json.Unmarshal(raw, &state); err != nil { t.Fatal(err) }
	if got := len(state.Rates[stablePolicyKey("rate", m.ClientIP)]); got != 10 {
		t.Fatalf("external writes overwritten: %d", got)
	}
	if action, _, err := a.EvaluateDeliveryPolicy(m, now.Add(10*time.Second)); err != nil || action != "soft_reject" {
		t.Fatalf("first store failed to reload peer state: %q %v", action, err)
	}
}
