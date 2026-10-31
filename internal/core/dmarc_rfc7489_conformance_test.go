package core

import (
    "context"
    "errors"
    "net"
    "strings"
    "testing"
)

func TestDMARCRFC7489RejectsAmbiguousPolicyRecords(t *testing.T) {
    cases := []struct{ name, record string }{
        {"duplicate p", "v=DMARC1; p=reject; p=none"},
        {"duplicate v", "v=DMARC1; v=DMARC2; p=reject"},
        {"v not first", "p=reject; v=DMARC1"},
        {"missing p", "v=DMARC1; rua=mailto:reports@example.org"},
        {"invalid percent", "v=DMARC1; p=reject; pct=101"},
        {"negative percent", "v=DMARC1; p=reject; pct=-1"},
        {"non-numeric percent", "v=DMARC1; p=reject; pct=half"},
        {"empty tag", "v=DMARC1;; p=reject"},
        {"malformed tag", "v=DMARC1; p=reject; unexpected"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            dns := stubDNS{txt: map[string][]string{"_dmarc.example.org": {tc.record}}}
            got := DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "fail"}, nil)
            if got.Result != "permerror" || got.Policy != "" {
                t.Fatalf("malformed policy must not be enforceable: %+v", got)
            }
        })
    }
}

func TestDMARCRFC7489DuplicateTXTIsPermerrorNotTemperror(t *testing.T) {
    dns := stubDNS{txt: map[string][]string{
        "_dmarc.example.org": {"v=DMARC1; p=reject", "v=DMARC1; p=none"},
    }}
    got := DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "fail"}, nil)
    if got.Result != "permerror" || !strings.Contains(got.Detail, "multiple") {
        t.Fatalf("duplicate policy records are permanent errors: %+v", got)
    }
    dns.txt = map[string][]string{
        "_dmarc.example.org": {"v=DMARC1; v=DMARC2; p=reject"},
    }
    got = DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "fail"}, nil)
    if got.Result != "permerror" {
        t.Fatalf("duplicated v must not hide a policy: %+v", got)
    }
}

func TestDMARCRFC7489InheritedInvalidPolicyAndUnknownTags(t *testing.T) {
    dns := stubDNS{txt: map[string][]string{
        "_dmarc.example.org": {"v=DMARC1; p=reject; p=none"},
    }}
    got := DMARCCheck(context.Background(), dns, "sender@sub.example.org", SPFResult{Result: "fail"}, nil)
    if got.Result != "permerror" {
        t.Fatalf("invalid inherited policy must remain permerror: %+v", got)
    }
    dns.txt["_dmarc.example.org"] = []string{"v=DMARC1; p=reject; x_vendor=enabled"}
    got = DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "fail"}, nil)
    if got.Result != "permerror" {
        t.Fatalf("invalid extension tag name must not be silently accepted: %+v", got)
    }
    dns.txt["_dmarc.example.org"] = []string{"v=DMARC1; p=reject; fo=1"}
    got = DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "fail"}, nil)
    if got.Result != "fail" || got.Policy != "reject" {
        t.Fatalf("valid unknown/optional tags must not invalidate policy: %+v", got)
    }
}

type temporaryDMARCDNS struct{ stubDNS }

func (temporaryDMARCDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
    return nil, &net.DNSError{Name: name, Err: "temporary DNS failure", IsTemporary: true}
}

func TestDMARCRFC7489TemporaryDNSRemainsTemperror(t *testing.T) {
    got := DMARCCheck(context.Background(), temporaryDMARCDNS{}, "sender@example.org", SPFResult{Result: "fail"}, nil)
    if got.Result != "temperror" {
        t.Fatalf("DNS failure must not become a permanent policy error: %+v", got)
    }
    if _, err := parseDMARCRecord("v=DMARC1; p=reject; p=none"); !errors.Is(err, errDMARCPolicy) {
        t.Fatalf("duplicate parser error must preserve policy sentinel: %v", err)
    }
}
