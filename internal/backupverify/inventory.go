package backupverify

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path"
 "path/filepath"
 "sort"
 "strings"
)

// BuildInventory creates a deterministic inventory of an already quiesced
// backup directory. It does not snapshot running SpamGate state.
// Every discovered file is reopened through the hardened verifier path.
func BuildInventory(root string) (Manifest, error) {
 m := Manifest{Version: 1}
 info, err := os.Lstat(root)
 if err != nil { return Manifest{}, err }
 if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
  return Manifest{}, errors.New("backup root must be a real directory")
 }
 var total int64
 err = filepath.WalkDir(root, func(name string, entry os.DirEntry, walkErr error) error {
  if walkErr != nil { return walkErr }
  if name == root { return nil }
  relative, err := filepath.Rel(root, name)
  if err != nil { return err }
  relative = filepath.ToSlash(relative)
  if entry.Type()&os.ModeSymlink != 0 { return fmt.Errorf("backup symlink refused: %q", relative) }
  if entry.IsDir() { return nil }
  if !entry.Type().IsRegular() {
   // Some filesystems return an unknown type; validate using Lstat.
   st, err := os.Lstat(name)
   if err != nil { return err }
   if !st.Mode().IsRegular() { return fmt.Errorf("nonregular backup entry: %q", relative) }
  }
  if len(m.Files) >= MaxFiles { return errors.New("backup inventory exceeds file limit") }
  if path.Clean(relative) != relative || strings.Contains(relative, "\\") {
   return fmt.Errorf("invalid backup inventory path %q", relative)
  }
  f, err := openVerifiedPath(root, relative)
  if err != nil { return err }
  st, err := f.Stat()
  if err != nil { f.Close(); return err }
  if !st.Mode().IsRegular() || st.Size() < 0 || st.Size() > MaxFileSize {
   f.Close()
   return fmt.Errorf("invalid backup file %q", relative)
  }
  before := st.ModTime()
  h := sha256.New()
  n, readErr := io.Copy(h, io.LimitReader(f, st.Size()+1))
  after, statErr := f.Stat()
  closeErr := f.Close()
  if statErr != nil { return statErr }
  if !os.SameFile(st, after) || st.Size() != after.Size() || !before.Equal(after.ModTime()) { return fmt.Errorf("backup file changed during inventory: %q", relative) }
  if readErr != nil { return readErr }
  if closeErr != nil { return closeErr }
  if n != st.Size() { return fmt.Errorf("backup file changed while reading: %q", relative) }
  if total > int64(MaxFiles)*MaxFileSize-n { return errors.New("backup inventory byte limit exceeded") }
  total += n
  m.Files = append(m.Files, Entry{Path: relative, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))})
  return nil
 })
 if err != nil { return Manifest{}, err }
 sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
 if err := ValidateManifest(m); err != nil { return Manifest{}, err }
 return m, nil
}

// VerifyComplete checks authenticated bytes and also rejects unlisted files,
// removed files, and extra paths. It is intended for an immutable backup tree.
// It is not an atomic snapshot or protection against concurrent modifications.
func VerifyComplete(root string, signed SignedManifest, key []byte) (Report, error) {
 if err := AuthenticateManifest(signed, key); err != nil { return Report{}, err }
 discovered, err := BuildInventory(root)
 if err != nil { return Report{}, err }
 expected := signed.Manifest.Files
 if len(discovered.Files) != len(expected) {
  return Report{}, fmt.Errorf("backup inventory differs: expected %d files, found %d", len(expected), len(discovered.Files))
 }
 byPath := make(map[string]Entry, len(expected))
 for _, entry := range expected { byPath[entry.Path] = entry }
 for _, actual := range discovered.Files {
  wanted, ok := byPath[actual.Path]
  if !ok || wanted.Size != actual.Size || wanted.SHA256 != actual.SHA256 {
   return Report{}, fmt.Errorf("backup inventory mismatch at %q", actual.Path)
  }
 }
 // Reopen through the existing descriptor-relative verifier, retaining its
 // safety properties for every authenticated file.
 return Verify(root, signed.Manifest)
}
