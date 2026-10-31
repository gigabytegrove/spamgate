package core

import (
    "errors"
    "fmt"
    "strconv"
    "strings"
)

var errDMARCPolicy = errors.New("invalid DMARC policy")

// dmarcCandidate intentionally checks every v tag, not the last map value.
// Otherwise a duplicated v= tag could hide a malformed DMARC policy as absent.
func dmarcCandidate(record string) bool {
    for _, field := range strings.Split(record, ";") {
        key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
        if ok && strings.EqualFold(strings.TrimSpace(key), "v") &&
            strings.EqualFold(strings.TrimSpace(value), "DMARC1") {
            return true
        }
    }
    return false
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
        if i == 0 && (key != "v" || !strings.EqualFold(value, "DMARC1")) {
            return nil, fmt.Errorf("%w: v=DMARC1 must be first", errDMARCPolicy)
        }
        if _, exists := tags[key]; exists {
            return nil, fmt.Errorf("%w: duplicate %s tag", errDMARCPolicy, key)
        }
        tags[key] = value
    }
    if !strings.EqualFold(tags["v"], "DMARC1") || tags["p"] == "" {
        return nil, fmt.Errorf("%w: missing required v or p tag", errDMARCPolicy)
    }
    if pct, exists := tags["pct"]; exists {
        n, err := strconv.Atoi(pct)
        if err != nil || len(pct) > 3 || n < 0 || n > 100 {
            return nil, fmt.Errorf("%w: pct must be between 0 and 100", errDMARCPolicy)
        }
    }
    return tags, nil
}
