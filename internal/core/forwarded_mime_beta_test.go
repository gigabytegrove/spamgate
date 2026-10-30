package core

import (
    "encoding/base64"
    "fmt"
    "strings"
    "testing"
)

// Fixtures are generated locally and never contact external mail or DNS.
func forwardedMIMEFixture(inner, transfer string) []byte {
    payload := inner
    encoding := ""
    if transfer == "base64" {
        payload = base64.StdEncoding.EncodeToString([]byte(inner))
        encoding = "Content-Transfer-Encoding: base64\r\n"
    }
    return []byte("From: sender@example.org\r\n" +
        "MIME-Version: 1.0\r\n" +
        "Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
        "--outer\r\nContent-Type: message/rfc822\r\n" + encoding +
        "\r\n" + payload + "\r\n--outer--\r\n")
}

func nestedExecutableMessage() string {
    return "From: sender@example.org\r\n" +
        "MIME-Version: 1.0\r\n" +
        "Content-Type: multipart/mixed; boundary=inner\r\n\r\n" +
        "--inner\r\nContent-Type: application/octet-stream; name=notes.dat\r\n" +
        "Content-Disposition: attachment; filename=notes.dat\r\n\r\n" +
        "MZ executable payload\r\n--inner--\r\n"
}

func hasAttachmentSymbol(items []AttachmentFinding, wanted string) bool {
    for _, item := range items {
        if item.Symbol == wanted { return true }
    }
    return false
}

func TestForwardedRFC822ExecutableInspection(t *testing.T) {
    for _, transfer := range []string{"plain", "base64"} {
        t.Run(transfer, func(t *testing.T) {
            found, err := InspectMIMEAttachments(forwardedMIMEFixture(nestedExecutableMessage(), transfer))
            if err != nil { t.Fatal(err) }
            if !hasAttachmentSymbol(found, "ATTACHMENT_EXECUTABLE_CONTENT") {
                t.Fatalf("executable inside forwarded RFC822 was missed: %+v", found)
            }
        })
    }
}

func TestForwardedRFC822PhishingInspection(t *testing.T) {
    for _, transfer := range []string{"plain", "base64"} {
        t.Run(transfer, func(t *testing.T) {
            nested := "From: sender@example.org\r\nContent-Type: text/html\r\n\r\n" +
                "<a href=\"https://evil.example.com/login\">https://bank.example.com/login</a>"
            found := detectPhishingLinks(forwardedMIMEFixture(nested, transfer))
            if len(found) != 1 || !strings.Contains(found[0], "evil.example.com") {
                t.Fatalf("forwarded phishing link was missed: %v", found)
            }
            safe := "From: sender@example.org\r\nContent-Type: text/html\r\n\r\n" +
                "<a href=\"https://bank.example.com/login\">https://bank.example.com/login</a>"
            if benign := detectPhishingLinks(forwardedMIMEFixture(safe, transfer)); len(benign) != 0 {
                t.Fatalf("legitimate forwarded link was falsely scored: %v", benign)
            }
        })
    }
}

func TestMalformedForwardedMessageIsReportedWithoutPositiveScore(t *testing.T) {
    found, err := InspectMIMEAttachments(forwardedMIMEFixture("not an RFC822 message", "plain"))
    if err != nil { t.Fatal(err) }
    if !hasAttachmentSymbol(found, "MIME_MALFORMED") {
        t.Fatalf("malformed forwarded message was silently ignored: %+v", found)
    }
    for _, f := range found {
        if f.Score > 0 { t.Fatalf("malformed attachment was assigned a spam score: %+v", f) }
    }
}

func TestMultipartBeyondSharedPartLimitIsReported(t *testing.T) {
    var body strings.Builder
    body.WriteString("From: sender@example.org\r\nMIME-Version: 1.0\r\n")
    body.WriteString("Content-Type: multipart/mixed; boundary=limit\r\n\r\n")
    for i := 0; i < 65; i++ {
        fmt.Fprintf(&body, "--limit\r\nContent-Type: text/plain\r\n\r\nordinary text %d\r\n", i)
    }
    body.WriteString("--limit--\r\n")
    found, err := InspectMIMEAttachments([]byte(body.String()))
    if err != nil { t.Fatal(err) }
    if !hasAttachmentSymbol(found, "MIME_LIMIT") {
        t.Fatalf("uninspected MIME parts were not reported: %+v", found)
    }
    if len(found) > 20 { t.Fatalf("unbounded MIME findings: %d", len(found)) }
    if phishing := detectPhishingLinks([]byte(body.String())); len(phishing) != 0 {
        t.Fatalf("plain text incorrectly flagged as phishing: %v", phishing)
    }
}
