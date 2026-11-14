package transport

import (
 "net/netip"
 "strings"
)

// rspamdClientIP validates the claimed SMTP client identity independently of
// the HTTP socket peer. The HTTP peer must already pass its own trust policy.
func rspamdClientIP(raw string) (string, bool) {
 if raw == "" { return "", true }
 if strings.TrimSpace(raw) != raw { return "", false }
 addr, err := netip.ParseAddr(raw)
 if err != nil || addr.Zone() != "" || addr.Is4In6() { return "", false }
 return addr.String(), true
}
