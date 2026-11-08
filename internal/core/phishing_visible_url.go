package core

import (
	"html"
	"strings"
)

// phishingVisibleURLText normalizes invisible formatting characters that
// browsers do not display. A URL split by zero-width characters is still
// presented to a reader as a contiguous hostname. Do not strip ordinary
// whitespace: that would invent a URL across visibly separated words.
func phishingVisibleURLText(text string) string {
	text = html.UnescapeString(text)
	text = strings.TrimSpace(text)
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u200b', '\u200c', '\u200d', '\u2060', '\ufeff':
			return -1
		}
		return r
	}, text)
}
