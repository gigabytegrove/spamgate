package updater

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
)

// copyExecutable is used for migration and rollback; it must never follow
// a substituted symlink or publish a partially copied executable.
func copyExecutable(source, target string) error {
 return copyExecutableVerified(source, target, "")
}

// copyExecutableVerified checks the digest of the bytes actually copied,
// closing the gap between Pending() and promotion of the staged pathname.
func copyExecutableVerified(source, target, expectedSHA string) error {
 if expectedSHA != "" && !hexDigest.MatchString(expectedSHA) {
  return errors.New("invalid expected executable digest")
 }
 before, err := os.Lstat(source)
 if err != nil { return err }
 if !before.Mode().IsRegular() {
  return errors.New("executable source must be regular, not a symlink")
 }
 input, err := os.Open(source)
 if err != nil { return err }
 defer input.Close()
 opened, err := input.Stat()
 if err != nil { return err }
 if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
  return errors.New("executable source changed identity during open")
 }
 if expectedSHA != "" && (opened.Size() < 4096 || opened.Size() > maxBinary) {
  return errors.New("staged executable size outside permitted bounds")
 }
 parent := filepath.Dir(target)
 dirInfo, err := os.Lstat(parent)
 if err != nil { return err }
 if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm()&0022 != 0 {
  return errors.New("executable destination directory must be real and not group/world writable")
 }
 temp, err := os.CreateTemp(parent, ".spamgate-exe-*")
 if err != nil { return err }
 defer os.Remove(temp.Name())
 if err = temp.Chmod(0700); err != nil { temp.Close(); return err }
 hash := sha256.New()
 var n int64
 if expectedSHA != "" {
  n, err = io.Copy(io.MultiWriter(temp, hash), io.LimitReader(input, maxBinary+1))
 } else {
  n, err = io.Copy(io.MultiWriter(temp, hash), input)
 }
 after, statErr := input.Stat()
 if err == nil { err = statErr }
 if err == nil && (!os.SameFile(opened, after) || opened.Size() != after.Size() ||
  !opened.ModTime().Equal(after.ModTime()) || n != opened.Size()) {
  err = errors.New("executable source changed during copy")
 }
 if err == nil && expectedSHA != "" && !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), expectedSHA) {
  err = errors.New("staged executable checksum changed during promotion")
 }
 if err == nil { err = temp.Sync() }
 closeErr := temp.Close()
 if err != nil { return err }
 if closeErr != nil { return closeErr }
 if err = os.Rename(temp.Name(), target); err != nil { return err }
 if err = syncUpdateDir(parent); err != nil {
  return fmt.Errorf("executable published but destination directory sync failed: %w", err)
 }
 return nil
}
