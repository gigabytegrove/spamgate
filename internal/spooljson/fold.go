package spooljson

import (
    "strings"
    "unicode"
)

// foldJSONKey uses Unicode simple case folding, the same equivalence relation
// used by encoding/json when matching object names to Go struct fields.
// strings.ToLower is insufficient: for example, U+017F LONG S is EqualFold
// to ASCII 's' but lowercases to itself. A duplicate state key could otherwise
// overwrite the decoded delivery state while retaining matching digests.
//
// Canonicalizing each rune to the smallest member of its SimpleFold cycle
// avoids quadratic comparisons among untrusted object keys.
func foldJSONKey(key string) string {
    var out strings.Builder
    out.Grow(len(key))
    for _, r := range key {
        canonical := r
        for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
            if next < canonical {
                canonical = next
            }
        }
        out.WriteRune(canonical)
    }
    return out.String()
}
