package core

import (
    "strings"
    "testing"
)

// Duplicate routing metadata is ambiguous across MIME consumers. In particular,
// a scanner must not choose one Content-Type while a mail client chooses another.
func TestDuplicateMIMERoutingHeadersAreNotTreatedAsInspected(t *testing.T) {
    cases := []struct {
        name string
        headers string
    }{
        {"content type", "Content-Type: application/octet-stream\r\nContent-Type: text/plain\r\n"},
        {"content disposition", "Content-Disposition: attachment; filename=invoice.exe\r\nContent-Disposition: inline\r\n"},
        {"transfer encoding", "Content-Transfer-Encoding: binary\r\nContent-Transfer-Encoding: base64\r\n"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            raw := "From: sender@example.test\r\nTo: receiver@example.test\r\n" +
                "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=gate\r\n\r\n" +
                "--gate\r\n" + tc.headers + "\r\nMZpayload\r\n--gate--\r\n"
            findings, err := InspectMIMEAttachments([]byte(raw))
            if err != nil { t.Fatalf("inspect: %v", err) }
            var malformed bool
            for _, f := range findings {
                if f.Symbol == "MIME_MALFORMED" && strings.Contains(f.Detail, "Duplicate MIME routing header") {
                    malformed = true
                }
                if f.Symbol == "ATTACHMENT_EXECUTABLE_CONTENT" {
                    t.Fatalf("ambiguous part was inspected as definitive: %+v", findings)
                }
            }
            if !malformed { t.Fatalf("missing ambiguity finding: %+v", findings) }
        })
    }
}

func TestSingleMIMERoutingHeadersRemainInspectable(t *testing.T) {
    raw := "From: sender@example.test\r\nTo: receiver@example.test\r\n" +
        "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=gate\r\n\r\n" +
        "--gate\r\nContent-Type: application/octet-stream\r\n" +
        "Content-Disposition: attachment; filename=invoice.bin\r\n" +
        "Content-Transfer-Encoding: binary\r\n\r\nMZpayload\r\n--gate--\r\n"
    findings, err := InspectMIMEAttachments([]byte(raw))
    if err != nil { t.Fatalf("inspect: %v", err) }
    for _, f := range findings {
        if f.Symbol == "ATTACHMENT_EXECUTABLE_CONTENT" { return }
    }
    t.Fatalf("expected executable signature finding: %+v", findings)
}
