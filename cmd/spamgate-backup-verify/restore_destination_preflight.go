package main

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

// checkColdRestoreDestination validates the exact filesystem contract used by
// backupverify.RestoreColdContext before opening authentication material.
// This is advisory only: RestoreColdContext rechecks and atomically publishes.
func checkColdRestoreDestination(target string) error {
 if target == "" { return errors.New("restore target required") }
 abs, err := filepath.Abs(target)
 if err != nil { return err }
 abs = filepath.Clean(abs)
 if abs == string(filepath.Separator) { return errors.New("unsafe restore target") }
 parent := filepath.Dir(abs)
 if parent == abs { return errors.New("unsafe restore target") }
 // The restore implementation requires an existing, symlink-free parent.
 // Check every component, not just whether EvalSymlinks changes the string:
 // a symlink that resolves back to the same lexical path is still unsafe.
 for p := parent; ; p = filepath.Dir(p) {
  info, err := os.Lstat(p)
  if err != nil { return fmt.Errorf("restore parent: %w", err) }
  if info.Mode()&os.ModeSymlink != 0 { return errors.New("restore parent contains symlink") }
  if !info.IsDir() { return errors.New("restore parent is not a directory") }
  if p == string(filepath.Separator) { break }
 }
 if _, err := os.Lstat(abs); err == nil {
  return errors.New("restore target already exists")
 } else if !errors.Is(err, os.ErrNotExist) {
  return fmt.Errorf("restore target: %w", err)
 }
 return nil
}
