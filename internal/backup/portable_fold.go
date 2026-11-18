package backup

import (
    "strings"
    "unicode"
)

// portableFoldIdentity returns a deterministic Unicode simple-fold identity.
// strings.ToLower alone is insufficient: Unicode EqualFold treats the Kelvin
// sign as K and the long s as S, even though their lowercase forms differ.
// Choose the smallest rune in each SimpleFold cycle to make the key stable
// regardless of which spelling is encountered first.
func portableFoldIdentity(path string) string {
    var b strings.Builder
    b.Grow(len(path))
    for _, r := range path {
        minimum := r
        for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
            if next < minimum {
                minimum = next
            }
        }
        b.WriteRune(minimum)
    }
    return b.String()
}
