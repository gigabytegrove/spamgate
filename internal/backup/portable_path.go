package backup

import "strings"

// portableBackupPath prevents Windows device aliases, alternate data streams,
// and trailing-dot normalization from changing a backup entry's identity.
func portableBackupPath(name string) bool {
 for _, component := range strings.Split(name, "/") {
  if component == "" || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
   return false
  }
  if strings.ContainsAny(component, ":*?\"<>|") { return false }
  stem := component
  if dot := strings.IndexByte(stem, '.'); dot >= 0 { stem = stem[:dot] }
  upper := strings.ToUpper(stem)
  switch upper {
  case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
   return false
  }
  // Windows treats superscript one, two, and three as device digits too.
  // Reject those aliases even on Linux, before a backup can be restored
  // onto a filesystem with different device-name semantics.
  if strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT") {
   suffix := strings.TrimPrefix(strings.TrimPrefix(upper, "COM"), "LPT")
   switch suffix {
   case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
    return false
   }
  }
 }
 return true
}
