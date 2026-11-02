package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestNativePolicyMarkerSurvivesColdBackupRestoreWithoutRuntimeLock(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "data")
	store, err := core.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.Settings.RateLimitEnabled = true
		c.Settings.RateLimitPerHour = 10
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m := core.Message{Connector: "milter", ClientIP: "198.51.100.91", Action: "accept"}
	now := time.Date(2026, 11, 2, 17, 0, 0, 0, time.UTC)
	if _, _, err := store.EvaluateDeliveryPolicy(m, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(source, ".delivery-policy.lock")); err != nil {
		t.Fatalf("expected native runtime policy lock: %v", err)
	}
	archive := filepath.Join(root, "backup.zip")
	if err := Create(source, archive); err != nil {
		t.Fatal(err)
	}
	manifest, err := Verify(archive)
	if err != nil {
		t.Fatal(err)
	}
	foundMarker, foundState := false, false
	for _, entry := range manifest.Entries {
		switch entry.Path {
		case ".delivery-policy.initialized":
			foundMarker = true
		case "delivery-policy.json":
			foundState = true
		case ".delivery-policy.lock":
			t.Fatal("runtime policy lock included in backup")
		}
	}
	if !foundMarker || !foundState {
		t.Fatalf("backup lost enforcement evidence: marker=%v state=%v", foundMarker, foundState)
	}
	dest := filepath.Join(root, "restored")
	if err := Restore(archive, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, ".delivery-policy.lock")); !os.IsNotExist(err) {
		t.Fatalf("runtime lock restored: %v", err)
	}
	restored, err := core.Open(dest)
	if err != nil {
		t.Fatalf("restored enforcement evidence failed startup: %v", err)
	}
	for i := 1; i < 10; i++ {
		if action, _, err := restored.EvaluateDeliveryPolicy(m, now.Add(time.Duration(i)*time.Second)); err != nil || action != "" {
			t.Fatalf("restored allowance %d: action=%q err=%v", i, action, err)
		}
	}
	if action, _, err := restored.EvaluateDeliveryPolicy(m, now.Add(10*time.Second)); err != nil || action != "soft_reject" {
		t.Fatalf("restore reset rate counters: action=%q err=%v", action, err)
	}
}
