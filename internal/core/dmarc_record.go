package core

import (
    "errors"
    "fmt"
    "strings"
)

var errDMARCPolicy = errors.New("invalid DMARC policy")

// RFC 9989 requires v=DMARC1 as the first tag, with a case-sensitive value.
// A misplaced version tag is not a discoverable DMARC policy record.
func dmarcCandidate(record string) bool {
    first, _, _ := strings.Cut(strings.TrimSpace(record), ";")
    key, value, ok := strings.Cut(strings.TrimSpace(first), "=")
    return ok && strings.TrimSpace(key) == "v" && strings.TrimSpace(value) == "DMARC1"
}

// parseDMARCRecord enforces RFC 7489 policy tag syntax before any alignment
// result can be used. Unknown well-formed extension tags are retained but not
// interpreted; malformed or duplicate tags must not be silently overwritten.
func parseDMARCRecord(record string) (map[string]string, error) {
    tags := make(map[string]string)
    parts := strings.Split(record, ";")
    for i, part := range parts {
        part = strings.TrimSpace(part)
        if part == "" && i == len(parts)-1 {
            continue
        }
        if part == "" {
            return nil, fmt.Errorf("%w: empty policy tag", errDMARCPolicy)
        }
        key, value, ok := strings.Cut(part, "=")
        if !ok {
            return nil, fmt.Errorf("%w: malformed tag", errDMARCPolicy)
        }
        key = strings.ToLower(strings.TrimSpace(key))
        value = strings.TrimSpace(value)
        if key == "" || value == "" {
            return nil, fmt.Errorf("%w: empty tag name or value", errDMARCPolicy)
        }
        for j, c := range key {
            if !((c >= 'a' && c <= 'z') || (j > 0 && c >= '0' && c <= '9')) {
                return nil, fmt.Errorf("%w: invalid tag name %q", errDMARCPolicy, key)
            }
        }
        if i == 0 && (key != "v" || value != "DMARC1") {
            return nil, fmt.Errorf("%w: v=DMARC1 must be first", errDMARCPolicy)
        }
        if _, exists := tags[key]; exists {
            return nil, fmt.Errorf("%w: duplicate %s tag", errDMARCPolicy, key)
        }
        tags[key] = value
    }
    if tags["v"] != "DMARC1" {
        return nil, fmt.Errorf("%w: missing or invalid v=DMARC1", errDMARCPolicy)
    }
    // RFC 9989 makes p optional with a default of none. The historic pct
    // tag is ignored, regardless of its value, rather than changing policy.
    if tags["p"] == "" {
        tags["p"] = "none"
    }
    return tags, nil
}
