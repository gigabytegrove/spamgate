package backup

import (
	"os"
	"path/filepath"
	"testing"
)

// Simulates another operator/process creating the restore destination after
// Restore's initial Lstat but before the final atomic publication.
func TestPublishRestoredDirectoryRefusesConcurrentDestination(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "staged")
	dest := filepath.Join(root, "restore")
	if err := os.Mkdir(stage, 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(stage, "config.json"), []byte("new"), 0600); err != nil { t.Fatal(err) }
	if err := os.Mkdir(dest, 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(dest, "config.json"), []byte("existing"), 0600); err != nil { t.Fatal(err) }
	if err := publishRestoredDirectory(stage, dest); err == nil {
		t.Fatal("concurrent restore destination was overwritten")
	}
	got, err := os.ReadFile(filepath.Join(dest, "config.json"))
	if err != nil || string(got) != "existing" { t.Fatalf("existing data lost: %q %v", got, err) }
	got, err = os.ReadFile(filepath.Join(stage, "config.json"))
	if err != nil || string(got) != "new" { t.Fatalf("staged data lost: %q %v", got, err) }
}

func TestPublishRestoredDirectoryAtomicallyPublishesNewDestination(t *testing.T) {
	root := t.TempDir()
	stage := filepath.Join(root, "staged")
	dest := filepath.Join(root, "restore")
	if err := os.Mkdir(stage, 0700); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(stage, "events.jsonl"), []byte("durable"), 0600); err != nil { t.Fatal(err) }
	if err := publishRestoredDirectory(stage, dest); err != nil { t.Fatal(err) }
	got, err := os.ReadFile(filepath.Join(dest, "events.jsonl"))
	if err != nil || string(got) != "durable" { t.Fatalf("published restore differs: %q %v", got, err) }
	if _, err := os.Lstat(stage); !os.IsNotExist(err) { t.Fatalf("staging directory not moved: %v", err) }
}
