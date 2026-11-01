package core

import (
    "context"
    "strings"
    "testing"
)

// Regression for the old self-assignment which silently discarded a DKIM
// alignment DNS outage, creating a false actionable DMARC fail.
func TestRFC9989DKIMAlignmentErrorRetention(t *testing.T) {
    policy := map[string][]string{
        "_dmarc.example.org": {"v=DMARC1; p=reject"},
        "_dmarc.other.net": {"v=DMARC1; p=none; psd=n"},
    }
    cases := []struct {
        name string
        spf SPFResult
        sigs []DKIMResult
        want string
    }{
        {"DNS outage then unaligned signature", SPFResult{Result:"fail"},
            []DKIMResult{{Result:"pass",Domain:"signer.example.org"},{Result:"pass",Domain:"other.net"}}, "temperror"},
        {"unaligned signature then DNS outage", SPFResult{Result:"fail"},
            []DKIMResult{{Result:"pass",Domain:"other.net"},{Result:"pass",Domain:"signer.example.org"}}, "temperror"},
        {"unaligned SPF then DKIM outage", SPFResult{Result:"pass",Domain:"other.net"},
            []DKIMResult{{Result:"pass",Domain:"signer.example.org"}}, "temperror"},
        {"aligned DKIM overrides DNS outage", SPFResult{Result:"fail"},
            []DKIMResult{{Result:"pass",Domain:"signer.example.org"},{Result:"pass",Domain:"example.org"}}, "pass"},
        {"definitively unaligned signature", SPFResult{Result:"fail"},
            []DKIMResult{{Result:"pass",Domain:"other.net"}}, "fail"},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            dns := &countingDMARCDNS{stubDNS: stubDNS{txt:policy},fail:"_dmarc.signer.example.org"}
            got := DMARCCheck(context.Background(), dns, "sender@example.org", tc.spf, tc.sigs)
            if got.Result != tc.want || got.Policy != "reject" {
                t.Fatalf("got %+v; want %s with original policy",got,tc.want)
            }
            if tc.want == "temperror" && !strings.Contains(got.Detail,"alignment") {
                t.Fatalf("DNS failure must remain explicit: %+v",got)
            }
        })
    }
}

func TestRFC9989DuplicateTXTDiscoveryRegression(t *testing.T) {
    cases := []struct {
        name, from, want, policy string
        records map[string][]string
        fail string
    }{
        {"direct conflict parent fallback","mail.example.org","fail","quarantine",
            map[string][]string{
                "_dmarc.mail.example.org":{"v=DMARC1; p=reject","v=DMARC1; p=none"},
                "_dmarc.example.org":{"v=DMARC1; p=quarantine; psd=n"},
            },""},
        {"intermediate conflict parent fallback","sub.mail.example.org","fail","quarantine",
            map[string][]string{
                "_dmarc.mail.example.org":{"v=DMARC1; p=reject","v=DMARC1; p=none"},
                "_dmarc.example.org":{"v=DMARC1; p=quarantine; psd=n"},
            },""},
        {"duplicate only","example.org","none","",
            map[string][]string{"_dmarc.example.org":{"v=DMARC1; p=reject","v=DMARC1; p=none"}},""},
        {"unrelated TXT ignored","example.org","fail","reject",
            map[string][]string{"_dmarc.example.org":{"other=record","v=DMARC1; p=reject"}},""},
        {"parent DNS failure remains temporary","mail.example.org","temperror","",
            map[string][]string{"_dmarc.mail.example.org":{"v=DMARC1; p=reject","v=DMARC1; p=none"}},"_dmarc.example.org"},
    }
    for _, tc := range cases {
        t.Run(tc.name,func(t *testing.T){
            dns:=&countingDMARCDNS{stubDNS:stubDNS{txt:tc.records},fail:tc.fail}
            got:=DMARCCheck(context.Background(),dns,"sender@"+tc.from,SPFResult{Result:"fail"},nil)
            if got.Result!=tc.want || got.Policy!=tc.policy {
                t.Fatalf("got %+v; want %s/%s; DNS %v",got,tc.want,tc.policy,dns.names)
            }
        })
    }
}
