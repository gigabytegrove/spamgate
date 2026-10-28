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

var anchorPattern = regexp.MustCompile(`(?is)<a\s+[^>]*?href\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))[^>]*>(.*?)</a\s*>`)
var stripMarkup = regexp.MustCompile(`(?s)<[^>]+>`)

// phishingVisibleLinks compares *visible* hostname claims to an actual link.
// Generic "view shipment" buttons are deliberately not scored. External
// redirect tracking requires expert review, so the detector is opt-in.
func phishingVisibleLinks(body string) []string {
	var findings []string
	for _, match := range anchorPattern.FindAllStringSubmatch(body, 50) {
		href := match[1] + match[2] + match[3]
		dest, err := url.Parse(strings.TrimSpace(html.UnescapeString(href)))
		if err != nil || (dest.Scheme != "https" && dest.Scheme != "http") {
			continue
		}
		destHost := strings.ToLower(strings.TrimSuffix(dest.Hostname(), "."))
		if !ValidReputationDomain(destHost) {
			continue
		}
		shown := strings.TrimSpace(html.UnescapeString(stripMarkup.ReplaceAllString(match[4], " ")))
		if len(shown) > 256 {
			continue
		}
		shown = strings.TrimSpace(shown)
		if !strings.HasPrefix(strings.ToLower(shown), "https://") && !strings.HasPrefix(strings.ToLower(shown), "http://") && !strings.HasPrefix(strings.ToLower(shown), "www.") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(shown), "www.") {
			shown = "https://" + shown
		}
		displayed, err := url.Parse(shown)
		if err != nil {
			continue
		}
		shownHost := strings.ToLower(strings.TrimSuffix(displayed.Hostname(), "."))
		if !ValidReputationDomain(shownHost) || shownHost == destHost || strings.HasSuffix(shownHost, "."+destHost) || strings.HasSuffix(destHost, "."+shownHost) {
			continue
		}
		findings = append(findings, fmt.Sprintf("Visible link claims %s but navigates to %s", shownHost, destHost))
		if len(findings) == 10 {
			break
		}
	}
	return findings
}

// walk decoded MIME text/html parts; avoid treating base64 attachment bytes as
// HTML. Per-part and nesting limits match the existing bounded MIME scanner.
func phishingMIME(h mail.Header, body []byte, depth int, out *[]string) {
	if depth > 8 || len(*out) >= 10 {
		return
	}
	media, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		return
	}
	if strings.HasPrefix(media, "multipart/") {
		if params["boundary"] == "" {
			return
		}
		r := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for i := 0; i < 75 && len(*out) < 10; i++ {
			part, err := r.NextPart()
			if err != nil {
				break
			}
			data, err := io.ReadAll(io.LimitReader(part, 2<<20))
			part.Close()
			if err == nil {
				phishingMIME(mail.Header(part.Header), data, depth+1, out)
			}
		}
		return
	}
	if media != "text/html" {
		return
	}
	var decoded []byte
	switch strings.ToLower(strings.TrimSpace(h.Get("Content-Transfer-Encoding"))) {
	case "base64":
		decoded = decodeBase64(body)
	case "quoted-printable":
		decoded = decodeQP(body)
	default:
		decoded = body
	}
	if len(decoded) > 2<<20 {
		decoded = decoded[:2<<20]
	}
	*out = append(*out, phishingVisibleLinks(string(decoded))...)
	if len(*out) > 10 {
		*out = (*out)[:10]
	}
}

func detectPhishingLinks(raw []byte) []string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(msg.Body, 10<<20))
	if err != nil {
		return nil
	}
	var found []string
	phishingMIME(msg.Header, body, 0, &found)
	return found
}
