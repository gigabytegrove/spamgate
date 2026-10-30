package core

import (
    "bytes"
    "fmt"
    "html"
    "io"
    "mime"
    "mime/multipart"
    "net/mail"
    "net/url"
    "regexp"
    "strings"
)

// Match complete opening tags, including quoted '>' characters. Attribute
// values are parsed separately so data-href and quoted text containing "href"
// cannot masquerade as the browser's actual destination.
var anchorPattern = regexp.MustCompile(`(?is)<a\b((?:[^>"']|"[^"]*"|'[^']*')*)>(.*?)</a\s*>`)
var htmlCommentPattern = regexp.MustCompile(`(?s)<!--.*?-->`)
var stripMarkup = regexp.MustCompile(`(?s)<[^>]+>`)

func htmlAttrSpace(b byte) bool {
    return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}
func htmlAttrName(b byte) bool {
    return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
        (b >= '0' && b <= '9') || b == '-' || b == '_' || b == ':'
}

// First occurrence wins, matching HTML attribute parsing for duplicate href.
// No regex searches inside other attribute values.
func anchorHref(attrs string) string {
    for i := 0; i < len(attrs); {
        for i < len(attrs) && htmlAttrSpace(attrs[i]) { i++ }
        start := i
        for i < len(attrs) && htmlAttrName(attrs[i]) { i++ }
        if start == i { i++; continue }
        name := attrs[start:i]
        for i < len(attrs) && htmlAttrSpace(attrs[i]) { i++ }
        if i >= len(attrs) || attrs[i] != '=' { continue }
        i++
        for i < len(attrs) && htmlAttrSpace(attrs[i]) { i++ }
        if i >= len(attrs) { return "" }
        var value string
        if attrs[i] == '"' || attrs[i] == '\'' {
            quote := attrs[i]
            i++
            start = i
            for i < len(attrs) && attrs[i] != quote { i++ }
            value = attrs[start:i]
            if i < len(attrs) { i++ }
        } else {
            start = i
            for i < len(attrs) && !htmlAttrSpace(attrs[i]) { i++ }
            value = attrs[start:i]
        }
        if strings.EqualFold(name, "href") { return value }
    }
    return ""
}

// Only score a visible URL hostname claim that conflicts with its actual
// destination. Buttons and ordinary redirect text remain unscored.
func phishingVisibleLinks(body string) []string {
    return phishingVisibleLinksWithCoverage(body, nil)
}

func phishingVisibleLinksWithCoverage(body string, coverage *mimeCoverage) []string {
    var findings []string
    // Comments are not browser-rendered links. Ignore them for scoring.
    body = htmlCommentPattern.ReplaceAllString(body, "")
    anchors := anchorPattern.FindAllStringSubmatch(body, 51)
    if len(anchors) > 50 {
        coverage.mark("More than 50 HTML anchors; remaining links not inspected")
        anchors = anchors[:50]
    }
    for anchorIndex, match := range anchors {
        href := strings.TrimSpace(html.UnescapeString(anchorHref(match[1])))
        if len(href) == 0 || len(href) > 4096 { continue }
        if strings.HasPrefix(href, "//") { href = "https:" + href }
        dest, err := url.Parse(href)
        if err != nil || (dest.Scheme != "https" && dest.Scheme != "http") { continue }
        destHost := strings.ToLower(strings.TrimSuffix(dest.Hostname(), "."))
        if !ValidReputationDomain(destHost) { continue }
        shown := strings.TrimSpace(html.UnescapeString(stripMarkup.ReplaceAllString(match[2], " ")))
        if len(shown) > 256 { continue }
        shownLower := strings.ToLower(shown)
        if !strings.HasPrefix(shownLower, "https://") && !strings.HasPrefix(shownLower, "http://") && !strings.HasPrefix(shownLower, "www.") { continue }
        if strings.HasPrefix(shownLower, "www.") { shown = "https://" + shown }
        displayed, err := url.Parse(shown)
        if err != nil { continue }
        shownHost := strings.ToLower(strings.TrimSuffix(displayed.Hostname(), "."))
        if !ValidReputationDomain(shownHost) || shownHost == destHost ||
            strings.HasSuffix(shownHost, "."+destHost) || strings.HasSuffix(destHost, "."+shownHost) {
            continue
        }
        findings = append(findings, fmt.Sprintf("Visible link claims %s but navigates to %s", shownHost, destHost))
        if len(findings) == 10 {
            if anchorIndex+1 < len(anchors) {
                coverage.mark("Phishing visible-link finding limit reached; remaining anchors not inspected")
            }
            break
        }
    }
    return findings
}

// The phishing path has its own bounded MIME traversal because it inspects
// rendered anchor destinations, not just the plain-text URL extractor. Any
// skipped portion is reported as zero-score diagnostic evidence. Incomplete
// inspection alone never changes an SMTP disposition.
func phishingMIME(h mail.Header, body []byte, depth int, out *[]string) {
    remaining := 75
    phishingMIMEWalkWithCoverage(h, body, depth, out, &remaining, &mimeCoverage{})
}

func phishingMIMEWalk(h mail.Header, body []byte, depth int, out *[]string, remaining *int) {
    phishingMIMEWalkWithCoverage(h, body, depth, out, remaining, &mimeCoverage{})
}

func phishingMIMEWalkWithCoverage(h mail.Header, body []byte, depth int, out *[]string, remaining *int, coverage *mimeCoverage) {
    if depth > 8 {
        coverage.mark("Phishing MIME nesting exceeds 8 levels")
        return
    }
    if len(*out) >= 10 {
        coverage.mark("Phishing visible-link finding limit reached")
        return
    }
    if *remaining <= 0 {
        coverage.mark("Phishing MIME part budget exhausted")
        return
    }
    contentType := h.Get("Content-Type")
    media, params, err := mime.ParseMediaType(contentType)
    if err != nil {
        if strings.TrimSpace(contentType) != "" {
            coverage.mark("Malformed phishing MIME Content-Type")
        }
        return
    }
    if strings.HasPrefix(media, "multipart/") {
        if params["boundary"] == "" {
            coverage.mark("Phishing MIME multipart boundary missing")
            return
        }
        reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
        for {
            if *remaining <= 0 {
                part, nextErr := reader.NextPart()
                if nextErr == nil {
                    _ = part.Close()
                    coverage.mark("More than 75 phishing MIME parts; remainder not inspected")
                } else if nextErr != io.EOF {
                    coverage.mark("Phishing MIME multipart termination invalid")
                }
                return
            }
            part, nextErr := reader.NextPart()
            if nextErr == io.EOF { return }
            if nextErr != nil {
                coverage.mark("Phishing MIME multipart section invalid")
                return
            }
            *remaining--
            data, readErr := io.ReadAll(io.LimitReader(part, (2<<20)+1))
            _ = part.Close()
            if readErr != nil {
                coverage.mark("Phishing MIME part read failed")
                continue
            }
            if len(data) > 2<<20 {
                coverage.mark("Phishing MIME part exceeds 2 MiB limit")
                continue
            }
            phishingMIMEWalkWithCoverage(mail.Header(part.Header), data, depth+1, out, remaining, coverage)
        }
    }
    if media == "message/rfc822" {
        payload, decodeErr := decodeMIMETextTransfer(body, h.Get("Content-Transfer-Encoding"))
        if decodeErr != nil {
            coverage.mark("Forwarded message transfer encoding invalid")
            return
        }
        if len(payload) > 2<<20 {
            coverage.mark("Forwarded message exceeds 2 MiB phishing limit")
            return
        }
        embedded, parseErr := mail.ReadMessage(bytes.NewReader(payload))
        if parseErr != nil {
            coverage.mark("Forwarded message cannot be parsed")
            return
        }
        inner, readErr := io.ReadAll(io.LimitReader(embedded.Body, (2<<20)+1))
        if readErr != nil || len(inner) > 2<<20 {
            coverage.mark("Forwarded message body exceeds phishing inspection limit")
            return
        }
        phishingMIMEWalkWithCoverage(embedded.Header, inner, depth+1, out, remaining, coverage)
        return
    }
    if media != "text/html" { return }
    // A detached HTML file is not a rendered message body. Treating its
    // anchor text as a visible email link creates avoidable false positives.
    if disposition, _, err := mime.ParseMediaType(h.Get("Content-Disposition")); err == nil && disposition == "attachment" {
        return
    }
    decoded, decodeErr := decodeMIMETextTransfer(body, h.Get("Content-Transfer-Encoding"))
    if decodeErr != nil {
        coverage.mark("Phishing HTML transfer encoding invalid")
        return
    }
    if len(decoded) > 2<<20 {
        coverage.mark("Decoded phishing HTML exceeds 2 MiB limit")
        return
    }
    matches := phishingVisibleLinksWithCoverage(string(decoded), coverage)
    available := 10-len(*out)
    if len(matches) > available {
        coverage.mark("Phishing visible-link finding limit reached")
        matches = matches[:available]
    }
    *out = append(*out, matches...)
}

// detectPhishingLinksWithCoverage reports inspection gaps without leaking
// message content or changing the classifier's configured scoring policy.
func detectPhishingLinksWithCoverage(raw []byte) ([]string, mimeCoverage) {
    coverage := mimeCoverage{}
    msg, err := mail.ReadMessage(bytes.NewReader(raw))
    if err != nil {
        coverage.mark("Phishing message headers cannot be parsed")
        return nil, coverage
    }
    body, err := io.ReadAll(io.LimitReader(msg.Body, (10<<20)+1))
    if err != nil || len(body) > 10<<20 {
        coverage.mark("Phishing message body exceeds 10 MiB limit or cannot be read")
        return nil, coverage
    }
    var found []string
    remaining := 75
    phishingMIMEWalkWithCoverage(msg.Header, body, 0, &found, &remaining, &coverage)
    return found, coverage
}

func detectPhishingLinks(raw []byte) []string {
    found, _ := detectPhishingLinksWithCoverage(raw)
    return found
}
