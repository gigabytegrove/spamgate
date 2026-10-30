package core

import (
	"context"
	"fmt"
	"net/mail"
	"strings"
	"testing"
)

func coverageMultipart(n int, suffix string) []byte {
	var b strings.Builder
	b.WriteString("From: sender@example.org\r\nTo: user@example.net\r\nDate: Fri, 30 Oct 2026 12:00:00 +0000\r\nMessage-ID: <coverage@example.org>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=limit\r\n\r\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "--limit\r\nContent-Type: text/plain\r\n\r\nordinary message part %d\r\n", i)
	}
	if suffix != "" {
		b.WriteString("--limit\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"")
		b.WriteString(suffix)
		b.WriteString("\"\r\n\r\nMZpayload\r\n")
	}
	b.WriteString("--limit--\r\n")
	return []byte(b.String())
}

func TestMIMEExtractionSharedPartBudgetDoesNotHideTruncation(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil { t.Fatal(err) }
	scanner := &Scanner{Store: st, Resolver: stubDNS{}}
	for _, tc := range []struct{name string; parts int; suffix string; incomplete bool}{
		{"ordinary", 4, "", false},
		{"exact_budget", 75, "", false},
		{"hidden_executable_after_budget", 75, "payload.exe", true},
		{"over_budget", 78, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := scanner.Scan(context.Background(), Input{Raw: coverageMultipart(tc.parts, tc.suffix), Sender: "sender@example.org", Recipients: []string{"user@example.net"}, Connector: "milter"})
			if err != nil { t.Fatal(err) }
			var diagnostic bool
			for _, f := range m.Findings {
				if f.Symbol == "MIME_COVERAGE_INCOMPLETE" {
					diagnostic = true
					if f.Score != 0 || f.Source != "diagnostic/mime" { t.Fatalf("unexpected disposition signal: %+v", f) }
				}
			}
			if diagnostic != tc.incomplete { t.Fatalf("coverage mismatch: %+v", m.Findings) }
			if m.Action == "reject" || m.Action == "quarantine" { t.Fatalf("coverage alone blocked benign mail: %s", m.Action) }
			if m.Scoring == nil { t.Fatal("missing scan trace") }
			var status string
			for _, check := range m.Scoring.Checks {
				if check.Name == "MIME text and filename coverage" { status = check.Status }
			}
			if tc.incomplete && status != "error" { t.Fatalf("incomplete extraction presented as %q", status) }
			if !tc.incomplete && status != "clear" { t.Fatalf("complete extraction presented as %q", status) }
		})
	}
}

func TestMIMEExtractionOversizedPartAndMalformedBoundary(t *testing.T) {
	for _, tc := range []struct{name string; header mail.Header; body []byte; reason string}{
		{"oversized", mail.Header{"Content-Type": {"multipart/mixed; boundary=big"}}, []byte("--big\r\nContent-Type: text/plain\r\n\r\n"+strings.Repeat("A", (5<<20)+1)+"\r\n--big--\r\n"), "5 MiB"},
		{"missing_boundary", mail.Header{"Content-Type": {"multipart/mixed"}}, []byte("not a MIME section"), "boundary"},
		{"malformed_boundary", mail.Header{"Content-Type": {"multipart/mixed; boundary=\"unterminated"}}, []byte("not a MIME section"), "Malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coverage := &mimeCoverage{}
			_, _, _, _ = bodyPartsWithCoverage(tc.header, tc.body, 0, coverage)
			if !coverage.Incomplete || !strings.Contains(strings.Join(coverage.Reasons, " "), tc.reason) {
				t.Fatalf("missing bounded coverage evidence: %+v", coverage)
			}
		})
	}
}

func TestMIMEExtractionDeepNestingAndURLCap(t *testing.T) {
	coverage := &mimeCoverage{}
	_, _, _, _ = bodyPartsWithCoverage(mail.Header{"Content-Type": {"text/plain"}}, []byte("body"), 9, coverage)
	if !coverage.Incomplete || !strings.Contains(strings.Join(coverage.Reasons, " "), "8 levels") { t.Fatalf("depth bypass: %+v", coverage) }
	var b strings.Builder
	for i := 0; i < 101; i++ { fmt.Fprintf(&b, "https://host%d.example.org/a ", i) }
	coverage = &mimeCoverage{}
	_, _, urls, _ := bodyPartsWithCoverage(mail.Header{"Content-Type": {"text/plain"}}, []byte(b.String()), 0, coverage)
	if len(urls) != 100 || !coverage.Incomplete { t.Fatalf("URL cap hidden: %d %+v", len(urls), coverage) }
}
