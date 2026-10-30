package core

import (
	"encoding/base64"
	"net/mail"
	"strings"
	"testing"
)

func TestMIMETextTransferStrictDecodeAndCoverage(t *testing.T) {
	cases := []struct {
		name string
		transfer string
		body string
		wantText string
		wantIncomplete bool
	}{
		{"plain", "7bit", "ordinary https://example.org/", "https://example.org/", false},
		{"base64", "base64", base64.StdEncoding.EncodeToString([]byte("ordinary https://example.org/")), "https://example.org/", false},
		{"quoted_printable", "quoted-printable", "ordinary=20https://example.org/", "https://example.org/", false},
		{"bad_base64", "base64", "%%%not-base64%%%", "", true},
		{"bad_qp", "quoted-printable", "hello=XXworld", "", true},
		{"unsupported", "x-uuencode", "ordinary https://example.org/", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coverage := &mimeCoverage{}
			h := mail.Header{"Content-Type": {"text/plain"}, "Content-Transfer-Encoding": {tc.transfer}}
			text, _, urls, _ := bodyPartsWithCoverage(h, []byte(tc.body), 0, coverage)
			if tc.wantText != "" && !strings.Contains(text, tc.wantText) { t.Fatalf("decoded content missing: %q", text) }
			if tc.wantText == "" && (text != "" || len(urls) != 0) { t.Fatalf("malformed transfer encoding was scanned as plaintext: %q %v", text, urls) }
			if coverage.Incomplete != tc.wantIncomplete { t.Fatalf("coverage mismatch: %+v", coverage) }
		})
	}
}

func TestMIMETextTransferDecodedLimitIsReported(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", (2<<20)+1)))
	coverage := &mimeCoverage{}
	text, _, _, _ := bodyPartsWithCoverage(mail.Header{"Content-Type": {"text/plain"}, "Content-Transfer-Encoding": {"base64"}}, []byte(body), 0, coverage)
	if len(text) != 2<<20 || !coverage.Incomplete || !strings.Contains(strings.Join(coverage.Reasons, " "), "2 MiB") {
		t.Fatalf("decoded-text truncation hidden: bytes=%d coverage=%+v", len(text), coverage)
	}
}

func TestMultipartTextPreservesRawQuotedPrintableForStrictValidation(t *testing.T){
    for _,tc:=range []struct{name,body string; incomplete bool; hasURL bool}{
        {"valid","https://example.org/?a=3Db",false,true},
        {"invalid","=ZZhttps://example.org",true,false},
    }{
        t.Run(tc.name,func(t *testing.T){
            body:="--boundary\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"+tc.body+"\r\n--boundary--\r\n"
            coverage:=&mimeCoverage{}
            _,_,urls,_:=bodyPartsWithCoverage(mail.Header{"Content-Type":{"multipart/mixed; boundary=boundary"}},[]byte(body),0,coverage)
            if coverage.Incomplete!=tc.incomplete||(len(urls)>0)!=tc.hasURL{
                t.Fatalf("multipart transfer bypass: urls=%+v coverage=%+v",urls,coverage)
            }
        })
    }
}
