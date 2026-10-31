package core

import (
    "context"
    "net"
    "strings"
    "testing"
)

func TestSPFRFC7208IncludeAndRedirectMissingPolicies(t *testing.T) {
    for _, tc := range []struct{ name, record string }{
        {"include NXDOMAIN", "v=spf1 include:absent.example.org -all"},
        {"include non-SPF TXT", "v=spf1 include:txtonly.example.org -all"},
        {"redirect NXDOMAIN", "v=spf1 redirect=absent.example.org"},
        {"redirect non-SPF TXT", "v=spf1 redirect=txtonly.example.org"},
    } {
        t.Run(tc.name, func(t *testing.T) {
            dns := stubDNS{txt: map[string][]string{
                "example.org": {tc.record},
                "txtonly.example.org": {"google-site-verification=ok"},
            }}
            got := SPFCheck(context.Background(), dns, "203.0.113.8", "sender@example.org", "")
            if got.Result != "permerror" || !strings.Contains(got.Explanation, "no SPF policy") {
                t.Fatalf("missing SPF target must be permerror, got %+v", got)
            }
        })
    }
}

func TestSPFRFC7208ModifiersAndPrevalidation(t *testing.T) {
    for _, tc := range []struct{ name, record, want string }{
        {"unknown modifier ignored", "v=spf1 vendor=xyz ip4:203.0.113.8 -all", "pass"},
        {"uppercase mechanism", "v=spf1 IP4:203.0.113.8 -all", "pass"},
        {"invalid trailing IP mechanism", "v=spf1 +all ip4:broken", "permerror"},
        {"invalid trailing mechanism", "v=spf1 +all invented", "permerror"},
        {"duplicate redirect", "v=spf1 redirect=first.example.org redirect=second.example.org", "permerror"},
        {"duplicate exp", "v=spf1 exp=first.example.org exp=second.example.org -all", "permerror"},
        {"empty redirect", "v=spf1 redirect=", "permerror"},
        {"invalid domain", "v=spf1 include:bad..example.org -all", "permerror"},
        {"unsupported macro", "v=spf1 exists:%{i}.example.org -all", "permerror"},
        {"invalid CIDR before matching", "v=spf1 +all a/24/64", "permerror"},
        {"invalid CIDR without DNS records", "v=spf1 a:missing.example.org/33 -all", "permerror"},
    } {
        t.Run(tc.name, func(t *testing.T) {
            dns := stubDNS{txt: map[string][]string{"example.org": {tc.record}}}
            got := SPFCheck(context.Background(), dns, "203.0.113.8", "sender@example.org", "")
            if got.Result != tc.want {
                t.Fatalf("got %+v, want %s", got, tc.want)
            }
        })
    }
}

func TestSPFRFC7208DualCIDRAndExistsAOnly(t *testing.T) {
    dns := stubDNS{
        txt: map[string][]string{
            "example.org": {"v=spf1 a:dual.example.org/24//64 -all"},
            "exists.example.org": {"v=spf1 exists:ipv6only.example.org -all"},
        },
        ips: map[string][]net.IPAddr{
            "dual.example.org": {{IP: net.ParseIP("192.0.2.20")}, {IP: net.ParseIP("2001:db8:42::1")}},
            "ipv6only.example.org": {{IP: net.ParseIP("2001:db8::1")}},
        },
    }
    for _, tc := range []struct{ ip, want string }{
        {"192.0.2.254", "pass"},
        {"2001:db8:42::ff", "pass"},
        {"192.0.3.1", "fail"},
        {"2001:db8:43::1", "fail"},
    } {
        got := SPFCheck(context.Background(), dns, tc.ip, "sender@example.org", "")
        if got.Result != tc.want {
            t.Errorf("dual CIDR %s: got %+v want %s", tc.ip, got, tc.want)
        }
    }
    got := SPFCheck(context.Background(), dns, "192.0.2.1", "sender@exists.example.org", "")
    if got.Result != "fail" {
        t.Fatalf("AAAA-only exists must not pass: %+v", got)
    }
    dns.ips["ipv6only.example.org"] = append(dns.ips["ipv6only.example.org"], net.IPAddr{IP: net.ParseIP("198.51.100.9")})
    got = SPFCheck(context.Background(), dns, "192.0.2.1", "sender@exists.example.org", "")
    if got.Result != "pass" {
        t.Fatalf("A RRset exists should pass: %+v", got)
    }
}

func TestSPFRFC7208VoidBudgetAndMissingMX(t *testing.T) {
    dns := stubDNS{txt: map[string][]string{
        "example.org": {"v=spf1 a:missing1.example.org mx:missing2.example.org a:missing3.example.org -all"},
    }}
    got := SPFCheck(context.Background(), dns, "192.0.2.1", "sender@example.org", "")
    if got.Result != "permerror" || !strings.Contains(got.Explanation, "void") {
        t.Fatalf("third NXDOMAIN must exceed void lookup limit: %+v", got)
    }
    dns.txt["example.org"] = []string{"v=spf1 mx:missing.example.org -all"}
    got = SPFCheck(context.Background(), dns, "192.0.2.1", "sender@example.org", "")
    if got.Result != "fail" {
        t.Fatalf("NXDOMAIN MX must fall through to -all: %+v", got)
    }
}
