package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeliveryPolicyPersistentMarkerPreventsUnseenCounterReset(t *testing.T) {
	dir := t.TempDir()
	// A starts before B creates the first persisted policy state.
	a := policyTestStore(t, dir, 10)
	b := policyTestStore(t, dir, 10)
	now := time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC)
	m := Message{Connector: "milter", ClientIP: "198.51.100.81", Action: "accept"}
	if _, _, err := b.EvaluateDeliveryPolicy(m, now); err != nil {
		t.Fatal(err)
	}
	if a.policyFileSeen {
		t.Fatal("test requires a worker that never observed the state file")
	}
	if err := os.Remove(filepath.Join(dir, "delivery-policy.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.EvaluateDeliveryPolicy(m, now.Add(time.Second)); err == nil ||
		!strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("uninitialized worker reset deleted counters: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "delivery-policy.json")); !os.IsNotExist(err) {
		t.Fatalf("lost policy evidence was recreated: %v", err)
	}
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("cold startup reset deleted counters: %v", err)
	}
}

func TestDeliveryPolicyMarkerFirstWriteAndRestart(t *testing.T) {
	dir := t.TempDir()
	s := policyTestStore(t, dir, 10)
	now := time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC)
	m := Message{Connector: "milter", ClientIP: "198.51.100.82", Action: "accept"}
	if _, _, err := s.EvaluateDeliveryPolicy(m, now); err != nil {
		t.Fatal(err)
	}
	exists, err := deliveryPolicyMarkerExists(dir)
	if err != nil || !exists {
		t.Fatalf("first write did not publish durable marker: exists=%v err=%v", exists, err)
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(reopened.policy.Rates[stablePolicyKey("rate", m.ClientIP)]); got != 1 {
		t.Fatalf("persisted rate counter after restart: %d", got)
	}
}

func TestDeliveryPolicyLegacyStateGetsPermanentMarker(t *testing.T) {
	dir := t.TempDir()
	// Existing installations have a state file but no marker.
	original := []byte("{\"greylist\":{},\"rates\":{}}")
	if err := os.WriteFile(filepath.Join(dir, "delivery-policy.json"), original, 0600); err != nil {
		t.Fatal(err)
	}
	s := policyTestStore(t, dir, 10)
	if _, _, err := s.EvaluateDeliveryPolicy(Message{
		Connector: "milter", ClientIP: "198.51.100.83", Action: "accept",
	}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	exists, err := deliveryPolicyMarkerExists(dir)
	if err != nil || !exists {
		t.Fatalf("legacy state was not marked: exists=%v err=%v", exists, err)
	}
}

func TestDeliveryPolicyMarkerCorruptionAndSymlinkRefuseWithoutReset(t *testing.T) {
	for _, mode := range []string{"corrupt", "symlink", "permissive"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			s := policyTestStore(t, dir, 10)
			m := Message{Connector: "milter", ClientIP: "198.51.100.84", Action: "accept"}
			now := time.Date(2026, 11, 2, 16, 0, 0, 0, time.UTC)
			if _, _, err := s.EvaluateDeliveryPolicy(m, now); err != nil {
				t.Fatal(err)
			}
			statePath := filepath.Join(dir, "delivery-policy.json")
			before, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			markerPath := filepath.Join(dir, deliveryPolicyMarkerName)
			switch mode {
			case "corrupt":
				if err := os.WriteFile(markerPath, []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(markerPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(statePath, markerPath); err != nil {
					t.Fatal(err)
				}
			case "permissive":
				if err := os.Chmod(markerPath, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := s.EvaluateDeliveryPolicy(m, now.Add(time.Second)); err == nil {
				t.Fatal("unsafe initialization evidence was accepted")
			}
			if _, err := Open(dir); err == nil {
				t.Fatal("cold start accepted unsafe initialization evidence")
			}
			after, err := os.ReadFile(statePath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("unsafe marker modified retained counters")
			}
		})
	}
}

func TestDeliveryPolicyInterruptedFirstPublicationFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := createDeliveryPolicyMarker(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "disappeared") {
		t.Fatalf("partial first publication silently bootstrapped: %v", err)
	}
}
