package transport

import (
 "errors"
 "net"
 "net/netip"
 "strconv"
 "strings"
)

// validateRelayEndpoint validates the destination before dialing or using it
// as the TLS peer name. Service-name ports and ambiguous hosts are rejected.
func validateRelayEndpoint(address string) (string, error) {
 host, port, err := net.SplitHostPort(address)
 if err != nil || host == "" || port == "" {
  return "", errors.New("relay endpoint must be an explicit host:port")
 }
 if strings.TrimSpace(host) != host || strings.ContainsAny(host, "\x00\r\n\t /\\@") {
  return "", errors.New("relay host contains invalid characters")
 }
 for _, c := range port {
  if c < '0' || c > '9' {
   return "", errors.New("relay port must be numeric")
  }
 }
 n, err := strconv.Atoi(port)
 if err != nil || n < 1 || n > 65535 {
  return "", errors.New("relay port must be between 1 and 65535")
 }
 if strings.Contains(host, "%") {
  return "", errors.New("relay IPv6 zone identifiers are unsupported")
 }
 if strings.Contains(host, ":") {
  ip, err := netip.ParseAddr(host)
  if err != nil || !ip.Is6() {
   return "", errors.New("invalid relay IPv6 host")
  }
  return host, nil
 }
 if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || len(host) > 253 {
  return "", errors.New("invalid relay DNS host")
 }
 if ip, err := netip.ParseAddr(host); err == nil {
  if !ip.Is4() {
   return "", errors.New("invalid relay IP address")
  }
  return host, nil
 }
 // Numeric dotted names must not bypass IP validation by being treated as DNS.
 numericDots := true
 for _, c := range host {
  if (c < '0' || c > '9') && c != '.' {
   numericDots = false
   break
  }
 }
 if numericDots {
  return "", errors.New("invalid relay IPv4 address")
 }
 for _, label := range strings.Split(host, ".") {
  if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
   return "", errors.New("invalid relay DNS label")
  }
  for _, c := range label {
   if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
    return "", errors.New("invalid relay DNS character")
   }
  }
 }
 return host, nil
}
