package core

import "strings"

// phishingInlineCSSHidden evaluates only literal inline display/visibility
// declarations. It never interprets CSS text inside strings, URLs, comments,
// custom properties or unrelated property values as a hiding instruction.
// This is deliberately not a full browser stylesheet/cascade implementation.
func phishingInlineCSSHidden(style string) bool {
	type declaration struct {
		value     string
		important bool
		set       bool
	}
	var display, visibility declaration
	for _, item := range phishingCSSDeclarations(style) {
		colon := strings.IndexByte(item, ':')
		if colon < 0 {
			continue
		}
		property := strings.ToLower(strings.TrimSpace(item[:colon]))
		if property != "display" && property != "visibility" {
			continue
		}
		value, important := phishingCSSValue(item[colon+1:])
		if !phishingCSSKnownValue(property, value) {
			continue
		}
		current := &display
		if property == "visibility" {
			current = &visibility
		}
		if !current.set || !current.important || important {
			*current = declaration{value: value, important: important, set: true}
		}
	}
	return display.value == "none" || visibility.value == "hidden" || visibility.value == "collapse"
}

// Split on declaration semicolons, not semicolons in quoted strings or
// parenthesized function values. Strip CSS comments outside strings.
func phishingCSSDeclarations(style string) []string {
	var parts []string
	var current strings.Builder
	var quote byte
	depth := 0
	for i := 0; i < len(style); i++ {
		c := style[i]
		if quote != 0 {
			current.WriteByte(c)
			if c == '\\' && i+1 < len(style) {
				i++
				current.WriteByte(style[i])
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '/' && i+1 < len(style) && style[i+1] == '*' {
			end := strings.Index(style[i+2:], "*/")
			if end < 0 {
				break
			}
			i += end + 3
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			current.WriteByte(c)
		case '(':
			depth++
			current.WriteByte(c)
		case ')':
			if depth > 0 {
				depth--
			}
			current.WriteByte(c)
		case ';':
			if depth == 0 {
				parts = append(parts, current.String())
				current.Reset()
			} else {
				current.WriteByte(c)
			}
		default:
			current.WriteByte(c)
		}
	}
	if quote == 0 && depth == 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func phishingCSSValue(input string) (string, bool) {
	value := strings.ToLower(strings.TrimSpace(input))
	// The !important marker may have whitespace between ! and important.
	end := len(value)
	for end > 0 && htmlAttrSpace(value[end-1]) {
		end--
	}
	start := end
	for start > 0 && value[start-1] >= 'a' && value[start-1] <= 'z' {
		start--
	}
	if value[start:end] == "important" {
		bang := start
		for bang > 0 && htmlAttrSpace(value[bang-1]) {
			bang--
		}
		if bang > 0 && value[bang-1] == '!' {
			return strings.TrimSpace(value[:bang-1]), true
		}
	}
	return value, false
}

func phishingCSSKnownValue(property, value string) bool {
	if property == "visibility" {
		switch value {
		case "visible", "hidden", "collapse", "initial", "inherit", "unset", "revert":
			return true
		}
		return false
	}
	switch value {
	case "none", "block", "inline", "inline-block", "flex", "inline-flex", "grid", "inline-grid", "contents", "table", "table-row", "table-cell", "list-item", "initial", "inherit", "unset", "revert":
		return true
	}
	return false
}
