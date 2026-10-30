package core

import (
    "context"
    "encoding/base64"
    "fmt"
    "strings"
    "testing"
)

const phishingMismatch = `<a href="https://evil.example.net/login">https://bank.example.com/login</a>`

func phishingFixture(contentType, encoding, disposition, body string) []byte {
    var b strings.Builder
    b.WriteString("From: sender@example.org\r\nTo: user@example.net\r\nDate: Fri, 30 Oct 2026 12:00:00 +0000\r\nMessage-ID: <phishing-coverage@example.org>\r\nMIME-Version: 1.0\r\n")
    b.WriteString("Content-Type: "+contentType+"\r\n")
    if encoding!="" { b.WriteString("Content-Transfer-Encoding: "+encoding+"\r\n") }
    if disposition!="" { b.WriteString("Content-Disposition: "+disposition+"\r\n") }
    b.WriteString("\r\n"+body)
    return []byte(b.String())
}

func TestPhishingStrictTransferAndAttachmentIsolation(t *testing.T) {
    cases:=[]struct{name,encoding,disposition,body string; want int; incomplete bool}{
        {"plain", "", "", phishingMismatch, 1, false},
        {"valid_base64", "base64", "", base64.StdEncoding.EncodeToString([]byte(phishingMismatch)), 1, false},
        {"valid_qp", "quoted-printable", "", strings.ReplaceAll(phishingMismatch, "=", "=3D"), 1, false},
        {"invalid_base64", "base64", "", "%%%%"+phishingMismatch, 0, true},
        {"invalid_qp", "quoted-printable", "", "=XX"+phishingMismatch, 0, true},
        {"unsupported_transfer", "x-custom", "", phishingMismatch, 0, true},
        {"html_attachment", "", "attachment; filename=\"invoice.html\"", phishingMismatch, 0, false},
    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            got,coverage:=detectPhishingLinksWithCoverage(phishingFixture("text/html",tc.encoding,tc.disposition,tc.body))
            if len(got)!=tc.want||coverage.Incomplete!=tc.incomplete {
                t.Fatalf("got %d findings and coverage %+v",len(got),coverage)
            }
        })
    }
}

func TestPhishingSharedPartBudgetAndMalformedMIME(t *testing.T) {
    var b strings.Builder
    for i:=0;i<76;i++ {
        fmt.Fprintf(&b,"--limit\r\nContent-Type: text/html\r\n\r\n%s\r\n", "<p>ordinary text</p>")
    }
    b.WriteString("--limit--\r\n")
    found,coverage:=detectPhishingLinksWithCoverage(phishingFixture("multipart/mixed; boundary=limit","","",b.String()))
    if len(found)!=0||!coverage.Incomplete||!strings.Contains(strings.Join(coverage.Reasons," "),"75"){
        t.Fatalf("part budget not reported: %+v %v",coverage,found)
    }
    _,coverage=detectPhishingLinksWithCoverage(phishingFixture("multipart/mixed","","","not multipart"))
    if !coverage.Incomplete {t.Fatal("missing boundary not reported")}
    _,coverage=detectPhishingLinksWithCoverage(phishingFixture("text/html","base64","",strings.Repeat("A",(3<<20)+4)))
    if !coverage.Incomplete {t.Fatal("oversized decoded HTML not reported")}
}

func TestPhishingCoverageEvidenceIsZeroScoreAndOptIn(t *testing.T) {
    st,err:=Open(t.TempDir());if err!=nil{t.Fatal(err)}
    scanner:=&Scanner{Store:st,Resolver:stubDNS{}}
    raw:=phishingFixture("text/html","base64","","%bad%")
    scan:=func() Message {
        t.Helper()
        m,e:=scanner.Scan(context.Background(),Input{Raw:raw,Sender:"sender@example.org",Recipients:[]string{"user@example.net"},Connector:"milter"})
        if e!=nil{t.Fatal(e)}
        return m
    }
    hasDiagnostic:=func(m Message)bool{
        for _,f:=range m.Findings {
            if f.Symbol=="PHISHING_COVERAGE_INCOMPLETE" {
                if f.Score!=0||f.Source!="diagnostic/phishing" {t.Fatalf("unsafe coverage signal: %+v",f)}
                return true
            }
        }
        return false
    }
    if hasDiagnostic(scan()){t.Fatal("disabled phishing inspection produced diagnostic")}
    if err:=st.UpdateConfig(func(c *Config)error{c.Settings.PhishingLinks=true;return nil});err!=nil{t.Fatal(err)}
    m:=scan()
    if !hasDiagnostic(m){t.Fatalf("missing coverage evidence: %+v",m.Findings)}
    if m.Action=="reject"||m.Action=="quarantine"{t.Fatalf("coverage alone blocked mail: %s",m.Action)}
    if m.Scoring==nil {t.Fatal("missing scoring trace")}
    for _,check:=range m.Scoring.Checks {
        if check.Name=="Visible-link impersonation" {
            if check.Status!="error"{t.Fatalf("coverage incorrectly reported %q",check.Status)}
            return
        }
    }
    t.Fatal("missing phishing scan trace")
}

func TestPhishingAnchorBudgetIsVisible(t *testing.T){
    html:=strings.Repeat(`<a href="https://example.org">https://example.org</a>`,51)
    coverage:=&mimeCoverage{}
    if got:=phishingVisibleLinksWithCoverage(html,coverage);len(got)!=0||!coverage.Incomplete{
        t.Fatalf("anchor truncation not reported: %+v %+v",coverage,got)
    }
}
