package main

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

// checkNativeBackupPaths enforces immutable installation boundaries even when
// --active-data points at a different directory. The authentication key must
// never be included in an inventory or reside inside either active data tree.
func checkNativeBackupPaths(active, backup, key, manifest string) error {
 const permanent = "/opt/spamgate/data"
 backupPath, err := resolveRestoreTarget(backup)
 if err != nil { return fmt.Errorf("resolve backup: %w", err) }
 activePath, err := resolveRestoreTarget(active)
 if err != nil { return fmt.Errorf("resolve active data: %w", err) }
 permanentPath, err := resolveRestoreTarget(permanent)
 if err != nil { return fmt.Errorf("resolve permanent data: %w", err) }
 keyPath, err := filepath.EvalSymlinks(key)
 if err != nil { return fmt.Errorf("resolve authentication key: %w", err) }
 keyPath, err = filepath.Abs(keyPath)
 if err != nil { return err }
 manifestPath, err := filepath.EvalSymlinks(manifest)
 if err != nil { return fmt.Errorf("resolve manifest: %w", err) }
 manifestPath, err = filepath.Abs(manifestPath)
 if err != nil { return err }
 overlap := func(a,b string) bool { return a == b || containsPath(a,b) || containsPath(b,a) }
 if overlap(backupPath, permanentPath) {
  return errors.New("backup root overlaps permanent SpamGate data")
 }
 if keyPath == backupPath || containsPath(backupPath,keyPath) {
  return errors.New("authentication key must remain outside backup")
 }
 if keyPath == activePath || containsPath(activePath,keyPath) || keyPath == permanentPath || containsPath(permanentPath,keyPath) {
  return errors.New("authentication key must remain outside active SpamGate data")
 }
 if keyPath == manifestPath { return errors.New("authentication key and manifest must be separate files") }
 if st, err := os.Stat(keyPath); err != nil || !st.Mode().IsRegular() {
  return errors.New("authentication key must be a regular file")
 }
 if st, err := os.Stat(manifestPath); err != nil || !st.Mode().IsRegular() {
  return errors.New("manifest must be a regular file")
 }
 return nil
}
