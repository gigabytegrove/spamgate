package backupverify

import "os"

// stableCopySource rejects replacement, truncation, extension, and metadata
// modification of an opened backup file during the restore copy. This is a
// detection boundary, not an atomic snapshot or protection against a writer
// that deliberately restores metadata after modifying the file.
func stableCopySource(before, after os.FileInfo) bool {
 if before == nil || after == nil {
  return false
 }
 return before.Mode().IsRegular() &&
  after.Mode().IsRegular() &&
  os.SameFile(before, after) &&
  before.Size() == after.Size() &&
  before.ModTime().Equal(after.ModTime())
}
