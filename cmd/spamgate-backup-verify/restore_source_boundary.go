package main

import (
 "errors"
 "fmt"
)

// checkRestoreSourceBoundary prevents cold restore from writing into the
// authenticated backup source or one of its ancestors. A restore must never
// destroy the only verified recovery copy.
func checkRestoreSourceBoundary(backup, target string) error {
 source, err := resolveRestoreTarget(backup)
 if err != nil { return fmt.Errorf("resolve backup source: %w", err) }
 destination, err := resolveRestoreTarget(target)
 if err != nil { return fmt.Errorf("resolve restore destination: %w", err) }
 if source == destination || containsPath(source, destination) || containsPath(destination, source) {
  return errors.New("restore destination overlaps backup source")
 }
 return nil
}
