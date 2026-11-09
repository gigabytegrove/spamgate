package core

import "strings"

// phishingBrowserHref applies the WHATWG URL preprocessing relevant to
// http(s) anchor destinations. Browsers discard ASCII tab, LF and CR before
// parsing, and treat backslashes as path separators for special URL schemes.
// Go's net/url does neither. Normalize only destinations, never visible text.
// The scheme check deliberately excludes javascript:, data:, mailto: and
// arbitrary schemes from backslash rewriting.
func phishingBrowserHref(href string) string {
	href = strings.Trim(href, "\x00\x09\x0a\x0c\x0d ")
	href = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, href)
	lower := strings.ToLower(href)
	if strings.HasPrefix(lower, "http:") || strings.HasPrefix(lower, "https:") || strings.HasPrefix(href, "//") || strings.HasPrefix(href, "\\\\") {
		href = strings.ReplaceAll(href, "\\", "/")
	}
	return href
}
