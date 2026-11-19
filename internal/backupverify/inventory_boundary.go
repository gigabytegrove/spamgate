package backupverify

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "strings"
)

// CreateSignedInventory signs an existing, quiesced backup directory.
// The caller must hold the key outside the backup tree and must ensure no
// application or other process is modifying the tree during inventory.
func CreateSignedInventory(root string, key []byte) (SignedManifest, error) {
 if err := validateKey(key); err != nil { return SignedManifest{}, err }
 m, err := BuildInventory(root)
 if err != nil { return SignedManifest{}, err }
 return SignManifest(m, key)
}

// CheckBackupBoundary rejects using the active SpamGate persistent directory
// as a backup source or destination, even through a symlink or nested path.
// Call this before any operator-facing backup workflow is allowed to run.
// It intentionally does not create or modify either directory.
func CheckBackupBoundary(activeData, backupRoot string) error {
 if activeData == "" || backupRoot == "" { return errors.New("active data and backup paths are required") }
 active, err := filepath.EvalSymlinks(activeData)
 if err != nil { return fmt.Errorf("resolve active data: %w", err) }
 backup, err := filepath.EvalSymlinks(backupRoot)
 if err != nil { return fmt.Errorf("resolve backup root: %w", err) }
 active, err = filepath.Abs(active)
 if err != nil { return err }
 backup, err = filepath.Abs(backup)
 if err != nil { return err }
 if active == backup { return errors.New("backup root cannot be active SpamGate data") }
 if inside(active, backup) || inside(backup, active) {
  return errors.New("backup and active SpamGate data must not contain one another")
 }
 a, err := os.Stat(active)
 if err != nil { return err }
 b, err := os.Stat(backup)
 if err != nil { return err }
 if !a.IsDir() || !b.IsDir() { return errors.New("backup boundary paths must be directories") }
 if os.SameFile(a, b) { return errors.New("backup root aliases active data") }
 return nil
}

func inside(parent, child string) bool {
 rel, err := filepath.Rel(parent, child)
 return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
