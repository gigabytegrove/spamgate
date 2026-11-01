package core

import (
    "context"
    "errors"
    "net"
    "reflect"
    "strings"
    "testing"
)

type countingDMARCDNS struct {
    stubDNS
    names []string
    fail string
}
func (d *countingDMARCDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
    d.names = append(d.names, name)
    if name == d.fail {
        return nil, &net.DNSError{Err: "temporary failure", Name: name, IsTemporary: true}
    }
    return d.stubDNS.LookupTXT(ctx, name)
}

func TestRFC9989TreeWalkQueryLimitAndOrder(t *testing.T) {
    cases := []struct{ domain string; targets []string }{
        {"a.example.org", []string{"a.example.org", "example.org", "org"}},
        {"a.b.c.d.e.f.g.h.i.j.mail.example.com", []string{
            "a.b.c.d.e.f.g.h.i.j.mail.example.com", "g.h.i.j.mail.example.com",
            "h.i.j.mail.example.com", "i.j.mail.example.com", "j.mail.example.com",
            "mail.example.com", "example.com", "com",
        }},
        {"a.b.c.d.e.f.g.h", []string{"a.b.c.d.e.f.g.h", "b.c.d.e.f.g.h", "c.d.e.f.g.h",
            "d.e.f.g.h", "e.f.g.h", "f.g.h", "g.h", "h"}},
    }
    for _, tc := range cases {
        if got := dmarcWalkTargets(tc.domain); !reflect.DeepEqual(got, tc.targets) {
            t.Errorf("%s: targets=%v want %v", tc.domain, got, tc.targets)
        }
        dns := &countingDMARCDNS{stubDNS: stubDNS{txt: map[string][]string{}}}
        w := newDMARCDNSWalk(context.Background(), dns)
        if _, err := w.walk(tc.domain); err != nil { t.Fatal(err) }
        var names []string
        for _, target := range tc.targets { names = append(names, "_dmarc."+target) }
        if !reflect.DeepEqual(dns.names, names) {
            t.Errorf("%s: actual DNS calls=%v want %v", tc.domain, dns.names, names)
        }
    }
}

func TestRFC9989TreeWalkPolicyPriority(t *testing.T) {
    cases := []struct {
        name, from string
        txt map[string][]string
        wantPolicy, wantResult string
    }{
        {"organizational record overrides intermediate", "a.mail.example.org", map[string][]string{
            "_dmarc.mail.example.org": {"v=DMARC1; p=quarantine"},
            "_dmarc.example.org": {"v=DMARC1; p=reject; sp=none; psd=n"},
        }, "none", "fail"},
        {"intermediate is org when no higher record", "a.mail.example.org", map[string][]string{
            "_dmarc.mail.example.org": {"v=DMARC1; p=reject"},
        }, "reject", "fail"},
        {"explicit lower org boundary", "a.mail.example.org", map[string][]string{
            "_dmarc.mail.example.org": {"v=DMARC1; p=quarantine; psd=n"},
            "_dmarc.example.org": {"v=DMARC1; p=reject"},
        }, "quarantine", "fail"},
        {"PSD fallback", "a.mail.example.org", map[string][]string{
            "_dmarc.example.org": {"v=DMARC1; p=reject; sp=quarantine; psd=y"},
        }, "quarantine", "fail"},
        {"org takes precedence over PSD", "a.mail.example.org", map[string][]string{
            "_dmarc.mail.example.org": {"v=DMARC1; p=none"},
            "_dmarc.example.org": {"v=DMARC1; p=reject; psd=y"},
        }, "none", "fail"},
        {"author takes precedence", "a.mail.example.org", map[string][]string{
            "_dmarc.a.mail.example.org": {"v=DMARC1; p=reject"},
            "_dmarc.mail.example.org": {"v=DMARC1; p=none; psd=n"},
        }, "reject", "fail"},
        {"no records", "a.mail.example.org", map[string][]string{}, "", "none"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            dns := stubDNS{txt: tc.txt}
            got := DMARCCheck(context.Background(), dns, "sender@"+tc.from, SPFResult{Result: "fail"}, nil)
            if got.Policy != tc.wantPolicy || got.Result != tc.wantResult {
                t.Fatalf("got %+v, want policy=%s result=%s", got, tc.wantPolicy, tc.wantResult)
            }
        })
    }
}

func TestRFC9989TreeWalkTenantBoundaryAlignment(t *testing.T) {
    dns := stubDNS{txt: map[string][]string{
        "_dmarc.platform.example.org": {"v=DMARC1; p=reject; psd=y"},
        "_dmarc.tenant1.platform.example.org": {"v=DMARC1; p=reject; psd=n"},
        "_dmarc.tenant2.platform.example.org": {"v=DMARC1; p=none; psd=n"},
    }}
    from := "sender@tenant1.platform.example.org"
    other := SPFResult{Result: "pass", Domain: "mail.tenant2.platform.example.org"}
    if got := DMARCCheck(context.Background(), dns, from, other, nil); got.Result != "fail" {
        t.Fatalf("independent tenant must not align: %+v", got)
    }
    own := SPFResult{Result: "pass", Domain: "mail.tenant1.platform.example.org"}
    if got := DMARCCheck(context.Background(), dns, from, own, nil); got.Result != "pass" {
        t.Fatalf("same organizational tenant should align: %+v", got)
    }
    if got := DMARCCheck(context.Background(), dns, from, other,
        []DKIMResult{{Result: "pass", Domain: "tenant1.platform.example.org"}}); got.Result != "pass" {
        t.Fatalf("aligned DKIM must override unaligned SPF: %+v", got)
    }
}

func TestRFC9989TreeWalkTransientAlignmentDNSDoesNotFailClosed(t *testing.T) {
    dns := &countingDMARCDNS{
        stubDNS: stubDNS{txt: map[string][]string{"_dmarc.example.org": {"v=DMARC1; p=reject"}}},
        fail: "_dmarc.mail.example.org",
    }
    got := DMARCCheck(context.Background(), dns, "sender@example.org",
        SPFResult{Result: "pass", Domain: "mail.example.org"}, nil)
    if got.Result != "temperror" || !strings.Contains(got.Detail, "alignment") {
        t.Fatalf("unresolved alignment cannot be an authentication failure: %+v", got)
    }
    got = DMARCCheck(context.Background(), dns, "sender@example.org",
        SPFResult{Result: "pass", Domain: "mail.example.org"},
        []DKIMResult{{Result: "pass", Domain: "example.org"}})
    if got.Result != "pass" { t.Fatalf("exact aligned DKIM should pass: %+v", got) }
}

func TestRFC9989TreeWalkRecordSafetyAndCaching(t *testing.T) {
    for _, bad := range []string{
        "v=DMARC1; p=reject; psd=maybe",
        "v=DMARC1; p=reject; t=maybe",
        "v=DMARC1; p=reject; np=bad",
    } {
        dns := stubDNS{txt: map[string][]string{"_dmarc.example.org": {bad}}}
        got := DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "fail"}, nil)
        if got.Result != "permerror" || got.Policy != "" {
            t.Fatalf("unsafe record %q must not enforce: %+v", bad, got)
        }
    }
    dns := &countingDMARCDNS{stubDNS: stubDNS{txt: map[string][]string{
        "_dmarc.example.org": {"v=DMARC1; p=reject"},
    }}}
    w := newDMARCDNSWalk(context.Background(), dns)
    if _, err := w.walk("a.example.org"); err != nil { t.Fatal(err) }
    if _, err := w.walk("b.example.org"); err != nil { t.Fatal(err) }
    count := 0
    for _, name := range dns.names { if name == "_dmarc.example.org" { count++ } }
    if count != 1 { t.Fatalf("shared suffix queried %d times", count) }
    if _, err := w.walk("not a domain"); !errors.Is(err, errDMARCPolicy) {
        t.Fatalf("invalid identifier should be rejected: %v", err)
    }
}
