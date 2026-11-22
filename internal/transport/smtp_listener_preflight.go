package transport

import (
 "errors"
 "fmt"
 "net"
 "net/netip"
 "strconv"
 "strings"
)

// validateListenerPreflight runs before binding any native SMTP socket.
// An incomplete or ambiguous trust boundary must never accept a message.
func (s *SMTP) validateListenerPreflight() error {
 if s == nil { return errors.New("SMTP listener is nil") }
 if s.Store == nil { return errors.New("SMTP listener requires persistent store") }
 if s.Scanner == nil || s.Scanner.Store == nil { return errors.New("SMTP listener requires initialized scanner") }
 if s.Scanner.Store != s.Store { return errors.New("SMTP scanner and listener must use the same persistent store") }
 if s.Queue == nil { return errors.New("SMTP listener requires durable delivery queue") }
 if s.Relay == nil { return errors.New("SMTP listener requires downstream relay") }
 if err := s.Relay.validateConfiguration(); err != nil { return fmt.Errorf("SMTP downstream relay: %w", err) }
 if err := validateSMTPListenAddress(s.Addr); err != nil { return err }
 if len(s.CIDRs) == 0 { return errors.New("SMTP listener requires explicit trusted CIDRs") }
 for _, network := range s.CIDRs {
  if err := validateSMTPTrustedCIDR(network); err != nil { return fmt.Errorf("SMTP listener invalid trusted CIDR: %w", err) }
 }
 if len(s.Domains) == 0 { return errors.New("SMTP listener requires explicit recipient domains") }
 seen := make(map[string]struct{}, len(s.Domains))
 for _, domain := range s.Domains {
  if !validSMTPRecipientDomain(strings.ToLower(domain)) || !isASCIIDomain(domain) {
   return errors.New("SMTP listener contains invalid recipient domain")
  }
  key := strings.ToLower(domain)
  if _, ok := seen[key]; ok { return errors.New("SMTP listener contains duplicate recipient domain") }
  seen[key] = struct{}{}
 }
 return nil
}

func isASCIIDomain(domain string) bool {
 for i := 0; i < len(domain); i++ { if domain[i] > 127 { return false } }
 return true
}

// Listen addresses are configuration, not SMTP envelope input. Reject
// service-name ports, zero ports, control characters and ambiguous hostnames.
// Bracketed IPv6 and explicit wildcard binds remain supported.
func validateSMTPListenAddress(address string) error {
 host, port, err := net.SplitHostPort(address)
 if err != nil || port == "" { return errors.New("SMTP listener requires valid host:port address") }
 if strings.ContainsAny(host, "\x00\r\n\t /\\") { return errors.New("SMTP listener contains invalid bind host") }
 for _, c := range port { if c < '0' || c > '9' { return errors.New("SMTP listener port must be numeric") } }
 n, err := strconv.Atoi(port)
 if err != nil || n < 1 || n > 65535 { return errors.New("SMTP listener port must be between 1 and 65535") }
 if strings.Contains(host, "%") { return errors.New("SMTP listener IPv6 zone identifiers are not supported") }
 return nil
}

// Validate manually constructed net.IPNet entries too, not just env parsing.
// A nil/short/noncontiguous mask must not be interpreted as a trusted peer.
func validateSMTPTrustedCIDR(network *net.IPNet) error {
 if network == nil { return errors.New("nil trusted CIDR") }
 addr, ok := netip.AddrFromSlice(network.IP)
 if !ok || addr.Is4In6() || addr.Zone() != "" { return errors.New("invalid trusted network IP") }
 addr = addr.Unmap()
 bits, total := network.Mask.Size()
 if bits < 0 || (addr.Is4() && total != 32) || (addr.Is6() && total != 128) {
  return errors.New("invalid trusted network mask")
 }
 prefix := netip.PrefixFrom(addr, bits)
 if !prefix.IsValid() || prefix.Masked() != prefix { return errors.New("trusted CIDR has host bits set") }
 return nil
}
