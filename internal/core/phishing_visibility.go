package core

import (
	"html"
	"strings"
)

// phishingRenderedHTML keeps only HTML that can contribute visible anchor
// text. Uncertain or malformed tags stop inspection rather than inventing a
// scored URL claim. This is not a browser or an external CSS renderer.
func phishingRenderedHTML(input string, coverage *mimeCoverage) string {
	if coverage == nil {
		coverage = &mimeCoverage{}
	}
	type frame struct {
		name   string
		hidden bool
	}
	// ASCII-only case folding preserves byte offsets for Unicode HTML and
	// avoids quadratic allocations across many raw-text elements.
	lowerBytes := []byte(input)
	for i, b := range lowerBytes {
		if b >= 'A' && b <= 'Z' {
			lowerBytes[i] = b + ('a' - 'A')
		}
	}
	lowerInput := string(lowerBytes)
	var out strings.Builder
	out.Grow(len(input))
	var stack []frame
	hidden := false
	for i := 0; i < len(input); {
		if input[i] != '<' {
			if !hidden {
				out.WriteByte(input[i])
			}
			i++
			continue
		}
		if strings.HasPrefix(input[i:], "<!--") {
			end := strings.Index(input[i+4:], "-->")
			if end < 0 {
				coverage.mark("Unterminated phishing HTML comment; remaining markup not inspected")
				break
			}
			i += 4 + end + 3
			continue
		}
		end, ok := phishingTagEnd(input, i)
		if !ok {
			coverage.mark("Unterminated phishing HTML tag; remaining markup not inspected")
			break
		}
		tag := input[i : end+1]
		name, closing, attrs, valid := phishingTagParts(tag)
		if !valid {
			// Declarations and malformed tags are not rendered anchors.
			i = end + 1
			continue
		}
		if closing {
			match := -1
			for j := len(stack) - 1; j >= 0; j-- {
				if stack[j].name == name {
					match = j
					break
				}
			}
			if match >= 0 {
				if !stack[match].hidden {
					out.WriteString(tag)
				}
				stack = stack[:match]
				hidden = len(stack) > 0 && stack[len(stack)-1].hidden
			}
			i = end + 1
			continue
		}
		selfClosing := strings.HasSuffix(strings.TrimSpace(tag[:len(tag)-1]), "/") || phishingVoidElement(name)
		nextHidden := hidden || phishingNonRenderedElement(name) || phishingHiddenAttributes(attrs)
		if !nextHidden {
			out.WriteString(tag)
		}
		i = end + 1
		if selfClosing {
			continue
		}
		if len(stack) >= 256 {
			coverage.mark("Phishing HTML nesting exceeds 256 elements; remaining markup not inspected")
			break
		}
		stack = append(stack, frame{name: name, hidden: nextHidden})
		hidden = nextHidden
		// Raw-text elements are not parsed as markup by HTML renderers.
		if name == "plaintext" {
			// HTML plaintext consumes the rest of the document as literal
			// text. Angle brackets below are not clickable anchor tags.
			break
		}
		if name == "script" || name == "style" || name == "textarea" || name == "title" ||
			name == "xmp" || name == "iframe" || name == "noembed" || name == "noframes" {
			lower := lowerInput[i:]
			needle := "</" + name
			position := 0
			found := false
			for position < len(lower) {
				p := strings.Index(lower[position:], needle)
				if p < 0 {
					break
				}
				p += position
				after := p + len(needle)
				if after == len(lower) || lower[after] == '>' || lower[after] == ' ' || lower[after] == '\t' || lower[after] == '\r' || lower[after] == '\n' {
					i += p
					found = true
					break
				}
				position = after
			}
			if !found {
				coverage.mark("Unterminated phishing HTML raw-text element; remaining markup not inspected")
				break
			}
		}
	}
	return out.String()
}

// Respect quoted greater-than signs when locating the end of an HTML tag.
// The caller already limits the decoded HTML to 2 MiB.
func phishingTagEnd(input string, start int) (int, bool) {
	var quote byte
	for i := start + 1; i < len(input); i++ {
		switch input[i] {
		case '\'', '"':
			if quote == 0 {
				quote = input[i]
			} else if quote == input[i] {
				quote = 0
			}
		case '>':
			if quote == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func phishingTagParts(tag string) (name string, closing bool, attrs string, valid bool) {
	i := 1
	if i < len(tag) && tag[i] == '/' {
		closing = true
		i++
	}
	for i < len(tag)-1 && htmlAttrSpace(tag[i]) {
		i++
	}
	start := i
	for i < len(tag)-1 && ((tag[i] >= 'a' && tag[i] <= 'z') || (tag[i] >= 'A' && tag[i] <= 'Z') || (tag[i] >= '0' && tag[i] <= '9') || tag[i] == '-') {
		i++
	}
	if start == i || !((tag[start] >= 'a' && tag[start] <= 'z') || (tag[start] >= 'A' && tag[start] <= 'Z')) {
		return "", false, "", false
	}
	return strings.ToLower(tag[start:i]), closing, tag[i : len(tag)-1], true
}

func phishingNonRenderedElement(name string) bool {
	switch name {
	case "script", "style", "template", "textarea", "title", "head", "noscript", "svg", "math",
		"select", "datalist", "option", "optgroup",
		"xmp", "iframe", "noembed", "noframes", "plaintext":
		return true
	}
	return false
}

func phishingVoidElement(name string) bool {
	switch name {
	case "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr":
		return true
	}
	return false
}

// Only attributes that suppress visual or pointer rendering are recognized.
// aria-hidden affects accessibility-tree exposure, not visual rendering;
// an aria-hidden anchor can still be clicked and must remain inspectable.
// A hidden="false" attribute still hides the element under HTML semantics.
func phishingHiddenAttributes(attrs string) bool {
	for i := 0; i < len(attrs); {
		for i < len(attrs) && (htmlAttrSpace(attrs[i]) || attrs[i] == '/') {
			i++
		}
		start := i
		for i < len(attrs) && htmlAttrName(attrs[i]) {
			i++
		}
		if start == i {
			i++
			continue
		}
		name := strings.ToLower(attrs[start:i])
		for i < len(attrs) && htmlAttrSpace(attrs[i]) {
			i++
		}
		value := ""
		if i < len(attrs) && attrs[i] == '=' {
			i++
			for i < len(attrs) && htmlAttrSpace(attrs[i]) {
				i++
			}
			if i < len(attrs) && (attrs[i] == '\'' || attrs[i] == '"') {
				quote := attrs[i]
				i++
				start = i
				for i < len(attrs) && attrs[i] != quote {
					i++
				}
				value = attrs[start:i]
				if i < len(attrs) {
					i++
				}
			} else {
				start = i
				for i < len(attrs) && !htmlAttrSpace(attrs[i]) {
					i++
				}
				value = attrs[start:i]
			}
		}
		switch name {
		case "hidden", "inert":
			return true
		case "style":
			if phishingInlineCSSHidden(html.UnescapeString(value)) {
				return true
			}
		}
	}
	return false
}
