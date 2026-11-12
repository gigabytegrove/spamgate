package backup

import (
 "errors"
 "fmt"
 "strings"
 "time"
)

// validateManifestSemantics checks invariants that JSON decoding alone does not
// establish. A forged archive must not supply impossible creation evidence or
// noncanonical digests that different consumers could interpret differently.
func validateManifestSemantics(m Manifest) error {
 if m.Created.IsZero() || m.Created.Year() < 2000 || m.Created.After(time.Now().UTC().Add(24*time.Hour)) {
  return errors.New("backup manifest creation time is missing or implausible")
 }
 for _, entry := range m.Entries {
  if len(entry.SHA256) != 64 {
   return fmt.Errorf("invalid SHA-256 length for %q", entry.Path)
  }
  for _, c := range entry.SHA256 {
   if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
    return fmt.Errorf("noncanonical SHA-256 digest for %q", entry.Path)
   }
  }
  if strings.TrimSpace(entry.Path) != entry.Path {
   return fmt.Errorf("noncanonical backup path %q", entry.Path)
  }
 }
 return nil
}
