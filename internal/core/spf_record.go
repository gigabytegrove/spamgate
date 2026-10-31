package core

// RFC 7208 record validation is performed before any mechanism can match.
// Otherwise "+all ip4:broken" would incorrectly authenticate malformed policy.
import (
    "errors"
    "fmt"
    "net"
    "strconv"
    "strings"
)

func spfValidDomain(domain string) bool {
    domain = strings.TrimSuffix(domain, ".")
    if len(domain) == 0 || len(domain) > 253 || !strings.Contains(domain, ".") {
        return false
    }
    for _, label := range strings.Split(domain, ".") {
        if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
            return false
        }
        for _, c := range label {
            if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '_') {
                return false
            }
        }
    }
    return true
}

// The RFC dual CIDR notation is /v4//v6, or //v6 when v4 is omitted.
// The first slash is consumed by the caller when splitting a mechanism.
func parseSPFDualCIDR(mask string) (int, int, error) {
    v4, v6 := 32, 128
    if mask == "" {
        return v4, v6, nil
    }
    parse := func(raw string, max int) (int, error) {
        if raw == "" {
            return 0, errors.New("empty SPF CIDR prefix")
        }
        n, err := strconv.Atoi(raw)
        if err != nil || n < 0 || n > max {
            return 0, fmt.Errorf("invalid SPF CIDR prefix %q (maximum %d)", raw, max)
        }
        return n, nil
    }
    if strings.HasPrefix(mask, "/") {
        n, err := parse(mask[1:], 128)
        return v4, n, err
    }
    if strings.Contains(mask, "//") {
        parts := strings.Split(mask, "//")
        if len(parts) != 2 {
            return 0, 0, errors.New("invalid SPF dual-CIDR")
        }
        n4, err := parse(parts[0], 32)
        if err != nil {
            return 0, 0, err
        }
        n6, err := parse(parts[1], 128)
        return n4, n6, err
    }
    n, err := parse(mask, 32)
    return n, v6, err
}

func spfModifierName(name string) bool {
    if len(name) == 0 || !((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) {
        return false
    }
    for _, c := range name[1:] {
        if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
            return false
        }
    }
    return true
}

func validateSPFRecord(fields []string) error {
    seen := map[string]bool{}
    for _, raw := range fields[1:] {
        if key, value, modifier := strings.Cut(raw, "="); modifier {
            if !spfModifierName(key) {
                return fmt.Errorf("invalid SPF modifier name %q", key)
            }
            key = strings.ToLower(key)
            if key == "redirect" || key == "exp" {
                if seen[key] {
                    return fmt.Errorf("duplicate SPF %s modifier", key)
                }
                seen[key] = true
                if value == "" || (key == "redirect" && !spfValidDomain(value)) {
                    return fmt.Errorf("invalid SPF %s modifier target", key)
                }
            }
            continue
        }
        term := raw
        if strings.ContainsRune("+-~?", rune(term[0])) {
            term = term[1:]
        }
        if term == "" || strings.HasSuffix(term, "/") {
            return fmt.Errorf("malformed SPF mechanism %q", raw)
        }
        mechanism, argument, colon := strings.Cut(term, ":")
        mask := ""
        if i := strings.IndexByte(mechanism, '/'); i >= 0 {
            if colon {
                return fmt.Errorf("malformed SPF mechanism %q", raw)
            }
            mask, mechanism = mechanism[i+1:], mechanism[:i]
        }
        if i := strings.IndexByte(argument, '/'); i >= 0 {
            if mask != "" {
                return fmt.Errorf("duplicate SPF CIDR %q", raw)
            }
            mask, argument = argument[i+1:], argument[:i]
        }
        switch strings.ToLower(mechanism) {
        case "all":
            if colon || mask != "" {
                return fmt.Errorf("invalid SPF all mechanism %q", raw)
            }
        case "a", "mx":
            if (colon && argument == "") || (argument != "" && !spfValidDomain(argument)) {
                return fmt.Errorf("invalid SPF DNS mechanism domain %q", raw)
            }
            if _, _, err := parseSPFDualCIDR(mask); err != nil {
                return err
            }
        case "include", "exists":
            if !colon || mask != "" || !spfValidDomain(argument) {
                return fmt.Errorf("invalid SPF %s mechanism %q", mechanism, raw)
            }
        case "ip4", "ip6":
            if !colon || argument == "" || strings.Contains(mask, "/") {
                return fmt.Errorf("invalid SPF IP mechanism %q", raw)
            }
            if mask == "" {
                if strings.EqualFold(mechanism, "ip4") {
                    mask = "32"
                } else {
                    mask = "128"
                }
            }
            _, network, err := net.ParseCIDR(argument + "/" + mask)
            if err != nil || (strings.EqualFold(mechanism, "ip4") && network.IP.To4() == nil) ||
                (strings.EqualFold(mechanism, "ip6") && network.IP.To4() != nil) {
                return fmt.Errorf("invalid SPF IP network %q", raw)
            }
        case "ptr":
            return errors.New("deprecated SPF ptr mechanism unsupported")
        default:
            return fmt.Errorf("unsupported SPF mechanism %q", mechanism)
        }
    }
    return nil
}
