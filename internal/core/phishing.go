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
    var findings []string
    // Comments are not browser-rendered links. Ignore them for scoring.
    body = htmlCommentPattern.ReplaceAllString(body, "")
    for _, match := range anchorPattern.FindAllStringSubmatch(body, 50) {
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
        if len(findings) == 10 { break }
    }
    return findings
}

// Walk decoded MIME text/html parts; avoid treating base64 attachment bytes as
// HTML. Per-part and nesting limits match the existing bounded MIME scanner.
func phishingMIME(h mail.Header, body []byte, depth int, out *[]string) {
    // One shared part budget for the complete MIME tree. Per-level budgets
    // allow an attacker to multiply work with nested multipart containers.
    remaining := 75
    phishingMIMEWalk(h, body, depth, out, &remaining)
}

func phishingMIMEWalk(h mail.Header, body []byte, depth int, out *[]string, remaining *int) {
    if depth > 8 || len(*out) >= 10 || *remaining <= 0 { return }
    media, params, err := mime.ParseMediaType(h.Get("Content-Type"))
    if err != nil { return }
    if strings.HasPrefix(media, "multipart/") {
        if params["boundary"] == "" { return }
        r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
        for *remaining > 0 && len(*out) < 10 {
            part, err := r.NextPart()
            if err != nil { break }
            *remaining--
            data, err := io.ReadAll(io.LimitReader(part, (2<<20)+1))
            _ = part.Close()
            if err == nil && len(data) <= 2<<20 {
                phishingMIMEWalk(mail.Header(part.Header), data, depth+1, out, remaining)
            }
        }
        return
    }
    if media == "message/rfc822" {
        // Inspect links inside attached/forwarded messages rather than
        // trusting an outer wrapper. Invalid or oversized content is skipped,
        // never treated as a positive phishing verdict.
        payload, err := attachmentPayload(body, h.Get("Content-Transfer-Encoding"))
        if err != nil || len(payload) > 2<<20 { return }
        embedded, err := mail.ReadMessage(bytes.NewReader(payload))
        if err != nil { return }
        inner, err := io.ReadAll(io.LimitReader(embedded.Body, (2<<20)+1))
        if err != nil || len(inner) > 2<<20 { return }
        phishingMIMEWalk(embedded.Header, inner, depth+1, out, remaining)
        return
    }
    if media != "text/html" { return }
    var decoded []byte
    switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
    case "base64":
        decoded = decodeBase64(body)
    case "quoted-printable":
        decoded = decodeQP(body)
    default:
        decoded = body
    }
    if len(decoded) > 2<<20 { return }
    *out = append(*out, phishingVisibleLinks(string(decoded))...)
    if len(*out) > 10 { *out = (*out)[:10] }
}

func detectPhishingLinks(raw []byte) []string {
    msg, err := mail.ReadMessage(bytes.NewReader(raw))
    if err != nil { return nil }
    body, err := io.ReadAll(io.LimitReader(msg.Body, (10<<20)+1))
    if err != nil || len(body) > 10<<20 { return nil }
    var found []string
    phishingMIME(msg.Header, body, 0, &found)
    return found
}
