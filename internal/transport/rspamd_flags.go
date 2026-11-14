package transport

import (
 "fmt"
 "strings"
)

// rspamdParseFlags accepts only flags whose semantics the compatibility worker
// actually implements. In particular, pass_all must not silently be ignored.
func rspamdParseFlags(raw string) (map[string]bool, error) {
 flags := make(map[string]bool)
 if raw == "" { return flags, nil }
 for _, part := range strings.Split(raw, ",") {
  flag := strings.TrimSpace(strings.ToLower(part))
  if flag == "" { return nil, fmt.Errorf("empty Rspamd flag") }
  if flags[flag] { return nil, fmt.Errorf("duplicate Rspamd flag: %s", flag) }
  switch flag {
  case "no_log", "milter":
   flags[flag] = true
  default:
   return nil, fmt.Errorf("unsupported Rspamd flag: %s", flag)
  }
 }
 return flags, nil
}
