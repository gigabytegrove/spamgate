package transport

import (
 "errors"
 "fmt"
 "net"
 "net/netip"
 "strings"
)

// parseRspamdTrustedNetworks uses the same canonical trust boundary as the
// native SMTP listener. An ambiguous CIDR must not silently widen access to
// the Rspamd-compatible HTTP scanning endpoint.
func parseRspamdTrustedNetworks(raw string) ([]*net.IPNet, error) {
 if strings.TrimSpace(raw) == "" {
  return nil, errors.New("Rspamd worker requires at least one trusted CIDR")
 }
 parts := strings.Split(raw, ",")
 if len(parts) > 128 {
  return nil, errors.New("Rspamd worker trusted network list exceeds 128 entries")
 }
 result := make([]*net.IPNet, 0, len(parts))
 seen := make(map[string]bool, len(parts))
 for index, part := range parts {
  value := strings.TrimSpace(part)
  if value == "" {
   return nil, fmt.Errorf("Rspamd trusted network entry %d is empty", index+1)
  }
  // A single literal IP is a host-only policy. Prefix-bearing values must
  // already be canonical; ParsePrefix masking is intentionally forbidden.
  if !strings.Contains(value, "/") {
   ip, err := netip.ParseAddr(value)
   if err != nil || ip.Zone() != "" || ip.Is4In6() ||
    (ip.Is6() && strings.Contains(value, ".")) {
    return nil, fmt.Errorf("Rspamd trusted network entry %d is not a valid unambiguous host address", index+1)
   }
   if ip.Is4() { value += "/32" } else { value += "/128" }
  }
  network, err := parseSMTPTrustedNetwork(value)
  if err != nil {
   return nil, fmt.Errorf("Rspamd trusted network entry %d (%q): %w", index+1, value, err)
  }
  canonical := network.String()
  if seen[canonical] {
   return nil, fmt.Errorf("Rspamd trusted network entry %d duplicates %s", index+1, canonical)
  }
  seen[canonical] = true
  result = append(result, network)
 }
 return result, nil
}
