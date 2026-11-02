package core

import "strings"

// phishingAnchorClaims tokenizes already visibility-filtered HTML. A regex
// would incorrectly treat literal <a> strings inside quoted attributes as
// clickable links, producing false-positive phishing scores.
type phishingAnchorClaim struct {
	href string
	text string
}

func phishingAnchorClaims(rendered string, coverage *mimeCoverage) []phishingAnchorClaim {
	if coverage == nil {
		coverage = &mimeCoverage{}
	}
	const maxClaims = 50
	const maxTextBytes = 4096
	claims := make([]phishingAnchorClaim, 0, 16)
	var text strings.Builder
	var href string
	active, tooLong := false, false

	finish := func() {
		if !active {
			return
		}
		if len(claims) <= maxClaims {
			if tooLong {
				coverage.mark("Phishing anchor text exceeds 4096 bytes; claim not scored")
			} else {
				claims = append(claims, phishingAnchorClaim{href: href, text: text.String()})
			}
		}
		active, tooLong, href = false, false, ""
		text.Reset()
	}
	addByte := func(b byte) {
		if !active || tooLong {
			return
		}
		if text.Len() == maxTextBytes {
			tooLong = true
			return
		}
		text.WriteByte(b)
	}
	for i := 0; i < len(rendered); {
		if rendered[i] != '<' {
			addByte(rendered[i])
			i++
			continue
		}
		end, ok := phishingTagEnd(rendered, i)
		if !ok {
			coverage.mark("Unterminated rendered phishing HTML tag; remaining links not inspected")
			break
		}
		name, closing, attrs, valid := phishingTagParts(rendered[i : end+1])
		if valid && name == "a" {
			if closing {
				finish()
			} else {
				// A new anchor implicitly closes a previous open anchor in
				// browser HTML parsing. Never merge their text or targets.
				finish()
				active = true
				href = anchorHref(attrs)
			}
		} else if active && valid {
			// Preserve whitespace separation across nested markup.
			addByte(' ')
		}
		i = end + 1
	}
	if active {
		coverage.mark("Unterminated phishing HTML anchor; unclosed claim not scored")
	}
	if len(claims) > maxClaims {
		coverage.mark("More than 50 HTML anchors; remaining links not inspected")
		return claims[:maxClaims]
	}
	return claims
}
