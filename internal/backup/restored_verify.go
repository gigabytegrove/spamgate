package backup

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "io/fs"
 "os"
 "path/filepath"
 "strings"
)

// VerifyRestored independently compares an existing, offline data tree with a
// fully validated backup archive. It never overwrites application data. On
// Linux the same nonblocking lock as the native worker is held for the check.
// Other writers must also be stopped; the worker lock is advisory.
func VerifyRestored(archive, destination string) (Manifest, error) {
 manifest, z, err := inspect(archive)
 if err != nil { return Manifest{}, err }
 defer z.Close()
 root, err := filepath.Abs(destination)
 if err != nil { return Manifest{}, err }
 info, err := os.Lstat(root)
 if err != nil { return Manifest{}, err }
 if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
  return Manifest{}, errors.New("restored data must be a real directory")
 }
 unlock, err := acquireOfflineLock(root)
 if err != nil { return Manifest{}, fmt.Errorf("offline restore verification refused: %w", err) }
 defer unlock()
 if err := verifyRestoredTree(manifest, root); err != nil { return Manifest{}, err }
 return manifest, nil
}

// verifyRestoredTree checks bytes as read back from disk, not just the bytes
// written during extraction. It also rejects unexpected files, directories,
// symlinks and special files. Only the exact ephemeral runtime lock paths are
// excluded from comparison; they must still be regular files.
func verifyRestoredTree(manifest Manifest, root string) error {
 want := make(map[string]Entry, len(manifest.Entries))
 dirs := map[string]bool{".": true}
 // A legitimate worker can recreate its ephemeral lock subdirectory.
 for _, lock := range []string{"delivery-queue/.delivery-worker.lock", "delivery-queue/.delivery-intake.lock"} {
  dirs[filepath.ToSlash(filepath.Dir(lock))] = true
 }
 for _, entry := range manifest.Entries {
  if !safeName(entry.Path) || runtimeLockPath(entry.Path) {
   if runtimeLockPath(entry.Path) { continue } // Older archives may contain verified runtime locks.
   return fmt.Errorf("unsafe restored manifest path %q", entry.Path)
  }
  if _, duplicate := want[entry.Path]; duplicate { return fmt.Errorf("duplicate restored manifest path %q", entry.Path) }
  want[entry.Path] = entry
  for dir := filepath.ToSlash(filepath.Dir(entry.Path)); dir != "."; dir = filepath.ToSlash(filepath.Dir(dir)) {
   dirs[dir] = true
  }
 }
 if len(want) == 0 { return errors.New("backup has no persistent files to verify") }
 seen := make(map[string]bool, len(want))
 err := filepath.WalkDir(root, func(path string, de fs.DirEntry, walkErr error) error {
  if walkErr != nil { return walkErr }
  rel, err := filepath.Rel(root, path)
  if err != nil { return err }
  rel = filepath.ToSlash(rel)
  info, err := os.Lstat(path)
  if err != nil { return err }
  if info.Mode()&os.ModeSymlink != 0 { return fmt.Errorf("restored tree contains a symlink: %q", rel) }
  if de.IsDir() {
   if !info.IsDir() || !dirs[rel] { return fmt.Errorf("unexpected restored directory: %q", rel) }
   return nil
  }
  if !info.Mode().IsRegular() { return fmt.Errorf("restored tree contains a non-regular file: %q", rel) }
  if runtimeLockPath(rel) { return nil }
  entry, exists := want[rel]
  if !exists || !safeName(rel) || seen[rel] { return fmt.Errorf("unexpected restored file: %q", rel) }
  seen[rel] = true
  if info.Size() != entry.Bytes { return fmt.Errorf("restored file size mismatch: %q", rel) }
  f, err := os.Open(path)
  if err != nil { return err }
  opened, err := f.Stat()
  if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
   f.Close()
   return fmt.Errorf("restored file changed during open: %q", rel)
  }
  h := sha256.New()
  n, readErr := io.Copy(h, io.LimitReader(f, entry.Bytes+1))
  finished, statErr := f.Stat()
  closeErr := f.Close()
  if readErr != nil { return readErr }
  if statErr != nil { return statErr }
  if closeErr != nil { return closeErr }
  if !os.SameFile(info, finished) || info.Size() != finished.Size() || !info.ModTime().Equal(finished.ModTime()) {
   return fmt.Errorf("restored file changed during verification: %q", rel)
  }
  if n != entry.Bytes || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), entry.SHA256) {
   return fmt.Errorf("restored file SHA-256 mismatch: %q", rel)
  }
  return nil
 })
 if err != nil { return err }
 if len(seen) != len(want) {
  for name := range want {
   if !seen[name] { return fmt.Errorf("restored file missing: %q", name) }
  }
 }
 return nil
}
