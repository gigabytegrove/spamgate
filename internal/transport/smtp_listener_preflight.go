package transport

import (
    "errors"
    "fmt"
    "net"
    "strings"
)

// validateListenerPreflight refuses to bind a native SMTP port unless the
// durable acceptance path and explicit trust boundaries are present.
// In particular, a zero-value SMTP must not panic after accepting a socket.
func (s *SMTP) validateListenerPreflight() error {
    if s == nil { return errors.New("SMTP listener is nil") }
    if s.Store == nil { return errors.New("SMTP listener requires persistent store") }
    if s.Scanner == nil || s.Scanner.Store == nil { return errors.New("SMTP listener requires initialized scanner") }
    if s.Scanner.Store != s.Store { return errors.New("SMTP scanner and listener must use the same persistent store") }
    if s.Queue == nil { return errors.New("SMTP listener requires durable delivery queue") }
    if s.Relay == nil { return errors.New("SMTP listener requires downstream relay") }
    if err := s.Relay.validateConfiguration(); err != nil { return fmt.Errorf("SMTP downstream relay: %w", err) }
    host, port, err := net.SplitHostPort(s.Addr)
    if err != nil || port == "" { return errors.New("SMTP listener requires valid host:port address") }
    _ = host // wildcard binds are permitted only with explicit trusted CIDRs.
    if len(s.CIDRs) == 0 { return errors.New("SMTP listener requires explicit trusted CIDRs") }
    for _, network := range s.CIDRs {
        if network == nil { return errors.New("SMTP listener contains nil trusted CIDR") }
    }
    if len(s.Domains) == 0 { return errors.New("SMTP listener requires explicit recipient domains") }
    seen := make(map[string]struct{}, len(s.Domains))
    for _, domain := range s.Domains {
        if domain == "" || !validSMTPRecipientDomain(domain) {
            return errors.New("SMTP listener contains invalid recipient domain")
        }
        for i := 0; i < len(domain); i++ {
            if domain[i] > 127 { return errors.New("SMTP listener contains non-ASCII recipient domain") }
        }
        key := strings.ToLower(domain)
        if _, ok := seen[key]; ok { return errors.New("SMTP listener contains duplicate recipient domain") }
        seen[key] = struct{}{}
    }
    return nil
}
