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
	// WHATWG special-scheme parsing treats surplus authority slashes as
	// separators. net/url instead leaves Host empty for https:////host.
	// Restrict this to explicit // authorities: a single slash or a bare
	// scheme can be relative to a document base and is not safely inferred.
	lower = strings.ToLower(href)
	for _, scheme := range []string{"http:", "https:"} {
		if strings.HasPrefix(lower, scheme+"///") {
			i := len(scheme)
			for i < len(href) && href[i] == '/' { i++ }
			href = href[:len(scheme)] + "//" + href[i:]
			break
		}
	}
	return href
}
