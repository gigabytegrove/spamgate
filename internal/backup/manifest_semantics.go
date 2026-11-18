package backup

import (
 "errors"
 "fmt"
 "strings"
 "time"
 "unicode"
 "unicode/utf8"
)

// validateManifestSemantics validates the complete version-one evidence
// contract before any archive entry is trusted or restored.
func validateManifestSemantics(m Manifest) error {
 if m.Format != 1 || m.Product != "SpamGate" {
  return errors.New("unsupported backup manifest format or product")
 }
 if m.Created.IsZero() || m.Created.Year() < 2000 || m.Created.After(time.Now().UTC().Add(24*time.Hour)) {
  return errors.New("backup manifest creation time is missing or implausible")
 }
 if len(m.Entries) == 0 || len(m.Entries) > maxFiles {
  return errors.New("backup manifest file count is outside supported bounds")
 }
 var total int64
 previous := ""
 seen := make(map[string]struct{}, len(m.Entries))
 // Windows and case-insensitive recovery targets cannot distinguish paths
 // that differ only by case. Reject ambiguous identities before extraction.
 folded := make(map[string]string, len(m.Entries))
 for i, entry := range m.Entries {
  if !safeName(entry.Path) || !canonicalBackupPath(entry.Path) {
   return fmt.Errorf("noncanonical backup path %q", entry.Path)
  }
  if i > 0 && entry.Path <= previous {
   return fmt.Errorf("backup manifest paths are not strictly ordered: %q", entry.Path)
  }
  // A complete ancestor set detects collisions even when sibling filenames intervene.
  // A file named "mail" cannot coexist with "mail/message.eml".
  for ancestor := entry.Path; ; {
   slash := strings.LastIndexByte(ancestor, '/')
   if slash < 0 { break }
   ancestor = ancestor[:slash]
   if _, exists := seen[ancestor]; exists {
    return fmt.Errorf("backup manifest file/directory collision: %q and %q", ancestor, entry.Path)
   }
  }
  identity := strings.ToLower(entry.Path)
  if prior, exists := folded[identity]; exists {
   return fmt.Errorf("backup manifest case-insensitive path collision: %q and %q", prior, entry.Path)
  }
  for ancestor := identity; ; {
   slash := strings.LastIndexByte(ancestor, '/')
   if slash < 0 { break }
   ancestor = ancestor[:slash]
   if prior, exists := folded[ancestor]; exists {
    return fmt.Errorf("backup manifest case-insensitive file/directory collision: %q and %q", prior, entry.Path)
   }
  }
  folded[identity] = entry.Path
  seen[entry.Path] = struct{}{}
  previous = entry.Path
  if entry.Bytes < 0 || entry.Bytes > maxBytes-total {
   return fmt.Errorf("backup manifest size exceeds limit for %q", entry.Path)
  }
  total += entry.Bytes
  if len(entry.SHA256) != 64 {
   return fmt.Errorf("invalid SHA-256 length for %q", entry.Path)
  }
  for _, c := range entry.SHA256 {
   if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
    return fmt.Errorf("noncanonical SHA-256 digest for %q", entry.Path)
   }
  }
 }
 return nil
}

// canonicalBackupPath prevents invisible or platform-dependent filenames from
// entering a portable disaster-recovery manifest. This check is intentionally
// stricter than the filesystem-level safeName guard.
func canonicalBackupPath(name string) bool {
 if !utf8.ValidString(name) || strings.TrimSpace(name) != name || !portableBackupPath(name) { return false }
 for _, r := range name {
  if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
   return false
  }
 }
 return true
}
