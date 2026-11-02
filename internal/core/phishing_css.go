package core

import (
	"math"
	"strconv"
	"strings"
)

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
	var display, visibility, opacity, contentVisibility declaration
	for _, item := range phishingCSSDeclarations(style) {
		colon := strings.IndexByte(item, ':')
		if colon < 0 {
			continue
		}
		property := strings.ToLower(strings.TrimSpace(item[:colon]))
		if property != "display" && property != "visibility" &&
			property != "opacity" && property != "content-visibility" {
			continue
		}
		value, important := phishingCSSValue(item[colon+1:])
		if !phishingCSSKnownValue(property, value) {
			continue
		}
		current := &display
		switch property {
		case "visibility":
			current = &visibility
		case "opacity":
			current = &opacity
		case "content-visibility":
			current = &contentVisibility
		}
		if !current.set || !current.important || important {
			*current = declaration{value: value, important: important, set: true}
		}
	}
	alpha, validAlpha := phishingCSSOpacity(opacity.value)
	return display.value == "none" ||
		visibility.value == "hidden" || visibility.value == "collapse" ||
		contentVisibility.value == "hidden" ||
		(validAlpha && alpha == 0)
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
	if property == "opacity" {
		_, ok := phishingCSSOpacity(value)
		return ok
	}
	if property == "content-visibility" {
		switch value {
		case "hidden", "visible", "auto", "initial", "inherit", "unset", "revert":
			return true
		}
		return false
	}
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

// phishingCSSOpacity accepts only literal CSS decimal numbers/percentages.
// Unknown expressions (var(), calc(), etc.) are not assumed to hide text.
// A zero-opacity element and its descendants cannot be made visible by
// overriding opacity on a child, unlike visibility or font-size inheritance.
func phishingCSSOpacity(value string) (float64, bool) {
	if value == "" {
		return 0, false
	}
	if strings.HasSuffix(value, "%") {
		value = strings.TrimSpace(strings.TrimSuffix(value, "%"))
	}
	if value == "" {
		return 0, false
	}
	for _, c := range value {
		if !strings.ContainsRune("0123456789.+-eE", c) {
			return 0, false
		}
	}
	n, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, false
	}
	return n, true
}
