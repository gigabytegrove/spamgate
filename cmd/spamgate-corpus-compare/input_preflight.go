package main

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
)

// openEvidence checks that the named corpus and opened descriptor identify the
// same regular file. This is not an immutable snapshot: writers must not modify
// evidence during qualification. An adversarial pathname replacement between
// Lstat and Open remains outside this check's security guarantee.
func openEvidence(path string) (*os.File, error) {
 if path == "" { return nil, errors.New("empty corpus path") }
 cleaned := filepath.Clean(path)
 info, err := os.Lstat(cleaned)
 if err != nil { return nil, fmt.Errorf("inspect corpus: %w", err) }
 if !info.Mode().IsRegular() { return nil, errors.New("corpus must be a regular file (no symlinks, pipes or devices)") }
 f, err := os.Open(cleaned)
 if err != nil { return nil, fmt.Errorf("open corpus: %w", err) }
 opened, err := f.Stat()
 if err != nil { f.Close(); return nil, err }
 if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
  f.Close()
  return nil, errors.New("corpus changed between inspection and opening")
 }
 return f, nil
}

func openEvidencePair(baselinePath, candidatePath string) (*os.File, *os.File, error) {
 b, err := openEvidence(baselinePath)
 if err != nil { return nil, nil, fmt.Errorf("baseline: %w", err) }
 c, err := openEvidence(candidatePath)
 if err != nil { b.Close(); return nil, nil, fmt.Errorf("candidate: %w", err) }
 bi, err := b.Stat()
 if err != nil { b.Close(); c.Close(); return nil, nil, err }
 ci, err := c.Stat()
 if err != nil { b.Close(); c.Close(); return nil, nil, err }
 if os.SameFile(bi, ci) {
  b.Close(); c.Close()
  return nil, nil, errors.New("baseline and candidate reference the same file")
 }
 return b, c, nil
}
