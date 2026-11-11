package core

import (
    "fmt"
    "strings"
    "testing"
)

// Each attachment has one executable signature finding. The exact-cap case
// must not claim evidence was lost, while the over-cap case must disclose it.
func mimeFindingBudgetFixture(parts int) []byte {
    var b strings.Builder
    b.WriteString("From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=budget\r\n\r\n")
    for i := 0; i < parts; i++ {
        fmt.Fprintf(&b, "--budget\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"payload-%02d.bin\"\r\n\r\nMZpayload\r\n", i)
    }
    b.WriteString("--budget--\r\n")
    return []byte(b.String())
}

func TestMIMEFindingBudgetBoundary(t *testing.T) {
    for _, tc := range []struct {
        name string
        parts int
        wantFindings int
        wantTruncated bool
    }{
        {"below-cap", 19, 19, false},
        {"exact-cap", 20, 20, false},
        {"above-cap", 21, 20, true},
        {"many-over-cap", 30, 20, true},
    } {
        t.Run(tc.name, func(t *testing.T) {
            findings, err := InspectMIMEAttachments(mimeFindingBudgetFixture(tc.parts))
            if err != nil { t.Fatal(err) }
            if len(findings) != tc.wantFindings {
                t.Fatalf("got %d findings, want %d: %+v", len(findings), tc.wantFindings, findings)
            }
            truncated := false
            for i, finding := range findings {
                if finding.Symbol == "MIME_FINDINGS_TRUNCATED" {
                    truncated = true
                    if i != len(findings)-1 { t.Fatalf("truncation marker must be final: %+v", findings) }
                }
            }
            if truncated != tc.wantTruncated {
                t.Fatalf("truncated=%v, want %v: %+v", truncated, tc.wantTruncated, findings)
            }
            if !truncated {
                for _, finding := range findings {
                    if finding.Symbol != "ATTACHMENT_EXECUTABLE_CONTENT" {
                        t.Fatalf("unexpected finding in complete inspection: %+v", findings)
                    }
                }
            }
        })
    }
}
