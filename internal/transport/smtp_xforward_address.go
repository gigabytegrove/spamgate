package transport

import (
    "net"
    "strings"
)

// parseSMTPXForwardAddress accepts Postfix XFORWARD ADDR's IPv4 and IPv6
// representations without trimming arbitrary brackets or prefixes. A malformed
// value must never become a different, valid client identity.
func parseSMTPXForwardAddress(value string) (string, bool) {
    if value == "" || strings.ContainsAny(value, "\r\n\x00") {
        return "", false
    }
    candidate := value
    if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
        if len(value) < 3 || value[0] != '[' || value[len(value)-1] != ']' {
            return "", false
        }
        candidate = value[1:len(value)-1]
    }
    if strings.HasPrefix(candidate, "IPv6:") {
        candidate = strings.TrimPrefix(candidate, "IPv6:")
        if !strings.Contains(candidate, ":") {
            return "", false
        }
    } else if strings.Contains(candidate, "IPv6:") {
        return "", false
    }
    ip := net.ParseIP(candidate)
    if ip == nil || strings.Contains(candidate, "%") {
        return "", false
    }
    return ip.String(), true
}
