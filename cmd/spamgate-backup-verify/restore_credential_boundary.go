package main

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

// checkRestoreCredentialBoundary prevents a cold restore from replacing or
// enclosing either input used to authenticate the recovery copy.
// It runs before the CLI reads credentials or creates the destination.
func checkRestoreCredentialBoundary(target, manifest, key string) error {
 destination, err := resolveRestoreTarget(target)
 if err != nil { return fmt.Errorf("resolve restore destination: %w", err) }
 for _, input := range []struct{name, path string}{
  {"authentication key", key}, {"signed manifest", manifest},
 } {
  resolved, err := filepath.EvalSymlinks(input.path)
  if err != nil { return fmt.Errorf("resolve %s: %w", input.name, err) }
  resolved, err = filepath.Abs(resolved)
  if err != nil { return err }
  info, err := os.Stat(resolved)
  if err != nil { return fmt.Errorf("stat %s: %w", input.name, err) }
  if !info.Mode().IsRegular() { return fmt.Errorf("%s must be a regular file", input.name) }
  if resolved == destination || containsPath(destination, resolved) {
   return fmt.Errorf("restore destination overlaps %s", input.name)
  }
  // Detect hardlink aliases when a destination already exists.
  if destInfo, err := os.Stat(destination); err == nil {
   if os.SameFile(info, destInfo) { return fmt.Errorf("restore destination aliases %s", input.name) }
  } else if !errors.Is(err, os.ErrNotExist) { return err }
 }
 return nil
}
