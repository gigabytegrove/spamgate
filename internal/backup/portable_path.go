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
  if len(upper) == 4 && (strings.HasPrefix(upper, "COM") || strings.HasPrefix(upper, "LPT")) && upper[3] >= '1' && upper[3] <= '9' { return false }
 }
 return true
}
