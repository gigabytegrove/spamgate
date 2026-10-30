package core

import (
    "archive/zip"
    "bytes"
    "encoding/base64"
    "fmt"
    "strings"
    "testing"
)

func betaZIP(t *testing.T, members map[string][]byte) []byte {
    t.Helper()
    var out bytes.Buffer
    zw := zip.NewWriter(&out)
    for name, content := range members {
        w, err := zw.Create(name)
        if err != nil { t.Fatal(err) }
        if _, err := w.Write(content); err != nil { t.Fatal(err) }
    }
    if err := zw.Close(); err != nil { t.Fatal(err) }
    return out.Bytes()
}

func betaZIPMessage(t *testing.T, payload []byte) []AttachmentFinding {
    t.Helper()
    encoded := base64.StdEncoding.EncodeToString(payload)
    raw := fmt.Sprintf("From: test@example.org\r\nTo: user@example.net\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=beta\r\n\r\n--beta\r\nContent-Type: application/zip; name=\"archive.zip\"\r\nContent-Disposition: attachment; filename=\"archive.zip\"\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n--beta--\r\n", encoded)
    findings, err := InspectMIMEAttachments([]byte(raw))
    if err != nil { t.Fatal(err) }
    return findings
}

func betaHasSymbol(findings []AttachmentFinding, symbol string) bool {
    for _, f := range findings { if f.Symbol == symbol { return true } }
    return false
}

func TestBetaZIPNestedExecutableSignature(t *testing.T) {
    nested := betaZIP(t, map[string][]byte{"report.dat": append([]byte("MZ"), bytes.Repeat([]byte{0}, 100)...)})
    outer := betaZIP(t, map[string][]byte{"documents/inside.zip": nested, "readme.txt": []byte("ordinary report")})
    findings := betaZIPMessage(t, outer)
    if !betaHasSymbol(findings, "ARCHIVE_EXECUTABLE_CONTENT") {
        t.Fatalf("nested executable with innocent filename escaped detection: %+v", findings)
    }
}

func TestBetaZIPOrdinaryDocumentsDoNotScore(t *testing.T) {
    nested := betaZIP(t, map[string][]byte{"readme.txt": []byte("hello world")})
    findings := betaZIPMessage(t, betaZIP(t, map[string][]byte{"archive.zip": nested, "invoice.txt": []byte("ordinary invoice")}))
    for _, f := range findings {
        if f.Score != 0 {
            t.Fatalf("false positive for benign nested ZIP: %+v", findings)
        }
    }
}

func TestBetaZIPTraversalAndWindowsAbsolutePaths(t *testing.T) {
    findings := betaZIPMessage(t, betaZIP(t, map[string][]byte{
        "../../escape.txt": []byte("x"),
        "C:\\windows\\evil.txt": []byte("x"),
        "safe/../escape.txt": []byte("x"),
    }))
    if !betaHasSymbol(findings, "ARCHIVE_TRAVERSAL_NAME") {
        t.Fatalf("archive traversal path not detected: %+v", findings)
    }
    for _, name := range []string{"../escape", "safe/../escape", "C:\\windows\\evil"} {
        if !archiveUnsafeName(name) { t.Fatalf("unsafe path accepted: %q", name) }
    }
    if archiveUnsafeName("reports/2026/summary.txt") { t.Fatal("benign path rejected") }
}

func TestBetaZIPRiskyFilenameAndHiddenExecutable(t *testing.T) {
    findings := betaZIPMessage(t, betaZIP(t, map[string][]byte{
        "statement.pdf.exe": []byte("MZnot-a-real-exe"),
        "innocent.bin": []byte{0x7f, 'E', 'L', 'F', 0, 0},
    }))
    if !betaHasSymbol(findings, "ARCHIVE_RISKY_MEMBER") || !betaHasSymbol(findings, "ARCHIVE_EXECUTABLE_CONTENT") {
        t.Fatalf("ZIP member metadata/content detection missing: %+v", findings)
    }
}

func TestBetaQuotedPrintableDecodedLimitIsNotSilent(t *testing.T) {
    oversized := bytes.Repeat([]byte("A"), (4<<20)+1)
    if _, err := attachmentPayload(oversized, "quoted-printable"); err == nil {
        t.Fatal("oversized decoded quoted-printable part was silently truncated")
    }
    decoded, err := attachmentPayload([]byte("hello=20world"), "quoted-printable")
    if err != nil || string(decoded) != "hello world" {
        t.Fatalf("valid quoted-printable part broken: %q, %v", decoded, err)
    }
    if _, err := attachmentPayload([]byte(strings.Repeat("=41", 100)), "quoted-printable"); err != nil {
        t.Fatalf("valid encoded data rejected: %v", err)
    }
}

func TestBetaZIPExpansionBudget(t *testing.T) {
    // Highly compressible content must trigger metadata limits without
    // attempting decompression of the oversized member.
    huge := bytes.Repeat([]byte("Z"), 31<<20)
    findings := betaZIPMessage(t, betaZIP(t, map[string][]byte{"compressed.txt": huge}))
    if !betaHasSymbol(findings, "ARCHIVE_EXPANSION_RISK") {
        t.Fatalf("declared expansion bomb not detected: %+v", findings)
    }
}
