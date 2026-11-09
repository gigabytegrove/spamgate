package core

import "strings"

// phishingBrowserHref follows the WHATWG URL parser's preprocessing for
// anchor href attributes: ASCII tab, LF and CR are removed anywhere in a
// URL before navigation. Go's net/url rejects these bytes instead, which
// otherwise lets a malicious destination evade visible-link mismatch checks.
// Only hrefs are normalized: displayed anchor text must retain its visible
// spacing to avoid inventing hostname claims.
func phishingBrowserHref(href string) string {
    href = strings.Trim(href, "\x00\x09\x0a\x0c\x0d ")
    return strings.Map(func(r rune) rune {
        if r == '\t' || r == '\n' || r == '\r' {
            return -1
        }
        return r
    }, href)
}
