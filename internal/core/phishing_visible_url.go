package core

import (
    "html"
    "strings"
)

// phishingInvisibleFormatting identifies characters which can alter the
// underlying URL without adding visible separation. Keep ordinary whitespace
// and printable Unicode intact: joining visible words would invent a claim.
func phishingInvisibleFormatting(r rune) bool {
    switch {
    case r == '\u00ad', // soft hyphen
         r == '\u034f', // combining grapheme joiner
         r == '\u061c', // Arabic letter mark
         r == '\u180e', // Mongolian vowel separator (legacy formatting)
         r >= '\u200b' && r <= '\u200f', // zero-width and directional marks
         r >= '\u202a' && r <= '\u202e', // bidi embeddings/overrides
         r >= '\u2060' && r <= '\u206f', // joiners, isolates and controls
         r == '\ufeff', // byte order mark
         r >= '\ufe00' && r <= '\ufe0f', // variation selectors
         r >= 0xe0100 && r <= 0xe01ef: // supplementary variation selectors
        return true
    }
    return false
}

// phishingVisibleURLText normalizes invisible formatting characters that
// browsers do not display. A URL split by formatting controls still appears
// contiguous. Never remove visible spaces or line breaks.
func phishingVisibleURLText(text string) string {
    text = html.UnescapeString(text)
    text = strings.TrimSpace(text)
    return strings.Map(func(r rune) rune {
        if phishingInvisibleFormatting(r) {
            return -1
        }
        return r
    }, text)
}
