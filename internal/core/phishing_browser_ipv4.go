package core

import (
 "net/netip"
 "strconv"
 "strings"
)

// phishingBrowserIPv4 recognizes legacy numeric IPv4 host spellings that
// browsers normalize before navigation. It never resolves DNS or makes a
// network request. Malformed spellings are rejected, not guessed.
func phishingBrowserIPv4(host string) (netip.Addr, bool) {
 host = strings.TrimSuffix(host, ".")
 if host == "" || len(host) > 128 { return netip.Addr{}, false }
 parts := strings.Split(host, ".")
 if len(parts) > 4 { return netip.Addr{}, false }
 values := make([]uint64, len(parts))
 for i, part := range parts {
  if part == "" { return netip.Addr{}, false }
  base, digits := 10, part
  if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") {
   base, digits = 16, part[2:]
  } else if len(part) > 1 && part[0] == '0' {
   base, digits = 8, part[1:]
  }
  // Do not infer a zero from an incomplete hex prefix.
  if digits == "" { return netip.Addr{}, false }
  n, err := strconv.ParseUint(digits, base, 32)
  if err != nil { return netip.Addr{}, false }
  values[i] = n
 }
 for _, n := range values[:len(values)-1] {
  if n > 255 { return netip.Addr{}, false }
 }
 lastBits := uint(8 * (5 - len(values)))
 if values[len(values)-1] > (uint64(1)<<lastBits)-1 { return netip.Addr{}, false }
 var ip uint64
 for i, n := range values[:len(values)-1] { ip |= n << uint(24-8*i) }
 ip |= values[len(values)-1]
 return netip.AddrFrom4([4]byte{byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)}), true
}
