package main

import (
 "errors"
 "fmt"
 "os"
)

// openEvaluationCorpus refuses symlinks, directories, FIFOs and devices.
// A qualification run must read a stable, finite regular file, not an
// attacker-controlled stream or an accidental live mail spool.
func openEvaluationCorpus(path string) (*os.File, os.FileInfo, error) {
 entry, err := os.Lstat(path)
 if err != nil { return nil,nil,err }
 if !entry.Mode().IsRegular() { return nil,nil,errors.New("corpus must be a regular file (symlinks and streams are refused)") }
 f, err := os.Open(path)
 if err != nil { return nil,nil,err }
 info, err := f.Stat()
 if err != nil { f.Close();return nil,nil,err }
 if !info.Mode().IsRegular() || !os.SameFile(entry,info) {
  f.Close()
  return nil,nil,errors.New("corpus file changed while opening")
 }
 return f,info,nil
}

// Check the opened descriptor, not merely its pathname: replacement and
// in-place edits must not silently yield a qualification result. This is
// best-effort filesystem stability detection, not a cryptographic snapshot;
// use --corpus-sha256 for independent evidence integrity.
func verifyEvaluationCorpusUnchanged(f *os.File, initial os.FileInfo) error {
 current,err:=f.Stat()
 if err!=nil{return err}
 if !os.SameFile(initial,current) || current.Size()!=initial.Size() || !current.ModTime().Equal(initial.ModTime()) || !evaluationCorpusChangeTimeEqual(initial,current) {
  return fmt.Errorf("regular corpus file was modified during evaluation")
 }
 return nil
}

// verifyEvaluationCorpusPathUnchanged also detects pathname replacement after
// the descriptor was opened. Descriptor-only checks miss rename/unlink attacks:
// the original inode can remain perfectly stable while the named evidence
// corpus has been replaced with unrelated data.
func verifyEvaluationCorpusPathUnchanged(path string, opened os.FileInfo) error {
 entry, err := os.Lstat(path)
 if err != nil { return fmt.Errorf("corpus path unavailable after evaluation: %w", err) }
 if !entry.Mode().IsRegular() || !os.SameFile(entry, opened) {
  return errors.New("corpus path was replaced or changed into a non-regular file")
 }
 if entry.Size()!=opened.Size() || !entry.ModTime().Equal(opened.ModTime()) || !evaluationCorpusChangeTimeEqual(opened,entry) {
  return errors.New("corpus path metadata changed during evaluation")
 }
 return nil
}
