package main

import (
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "syscall"
)

// openEvidence checks the opened inode rather than trusting a pathname.
// O_NOFOLLOW closes the Lstat/Open symlink-swap window on native Linux.
func openEvidence(path string) (*os.File, error) {
 if path == "" { return nil, errors.New("empty corpus path") }
 cleaned := filepath.Clean(path)
 info, err := os.Lstat(cleaned)
 if err != nil { return nil, fmt.Errorf("inspect corpus: %w", err) }
 if !info.Mode().IsRegular() { return nil, errors.New("corpus must be a regular file (no symlinks, pipes or devices)") }
 fd, err := syscall.Open(cleaned, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
 if err != nil { return nil, fmt.Errorf("open corpus without following symlinks: %w", err) }
 f := os.NewFile(uintptr(fd), cleaned)
 if f == nil { syscall.Close(fd); return nil, errors.New("could not wrap corpus descriptor") }
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
