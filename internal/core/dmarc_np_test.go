package core

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type dmarcStatusDNS struct {
	stubDNS
	nx bool
	err error
	calls []string
}

func (d *dmarcStatusDNS) DMARCNameNXDOMAIN(ctx context.Context, name string) (bool, error) {
	d.calls = append(d.calls, name)
	if err := ctx.Err(); err != nil { return false, err }
	return d.nx, d.err
}

func TestRFC9989NonexistentSubdomainPolicySelection(t *testing.T) {
	const from = "sender@invoice.example.org"
	record := "v=DMARC1; p=quarantine; sp=none; np=reject; psd=n"
	for _, tc := range []struct{
		name string
		nx bool
		wantPolicy string
	}{
		{"existing subdomain NODATA", false, "none"},
		{"nonexistent subdomain NXDOMAIN", true, "reject"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dns := &dmarcStatusDNS{stubDNS:stubDNS{txt:map[string][]string{
				"_dmarc.example.org":{record},
			}},nx:tc.nx}
			got := DMARCCheck(context.Background(), dns, from, SPFResult{Result:"fail"}, nil)
			if got.Result != "fail" || got.Policy != tc.wantPolicy {
				t.Fatalf("got %+v; want fail/%s",got,tc.wantPolicy)
			}
			if len(dns.calls)!=1 || dns.calls[0]!="invoice.example.org" {
				t.Fatalf("must query exact Author Domain once: %v",dns.calls)
			}
		})
	}
}

func TestRFC9989NonexistentPolicyNeverGuessesNXDOMAIN(t *testing.T) {
	record := "v=DMARC1; p=none; sp=none; np=reject; psd=n"
	dns := stubDNS{txt:map[string][]string{"_dmarc.example.org":{record}}}
	got := DMARCCheck(context.Background(),dns,"sender@invented.example.org",SPFResult{Result:"fail"},nil)
	if got.Result!="temperror" || got.Policy!="" || !strings.Contains(got.Detail,"NXDOMAIN") {
		t.Fatalf("TXT absence cannot prove NXDOMAIN: %+v",got)
	}
	withStatus := &dmarcStatusDNS{stubDNS:dns,err:errors.New("SERVFAIL")}
	got = DMARCCheck(context.Background(),withStatus,"sender@invented.example.org",SPFResult{Result:"fail"},nil)
	if got.Result!="temperror" || got.Policy!="" || !strings.Contains(got.Detail,"SERVFAIL") {
		t.Fatalf("transient DNS status cannot enforce np: %+v",got)
	}
	if len(withStatus.calls)!=1 { t.Fatalf("unexpected status calls: %v",withStatus.calls) }
}

func TestRFC9989NonexistentPolicyAvoidsUnnecessaryStatusQueries(t *testing.T) {
	record := "v=DMARC1; p=reject; sp=none; np=reject; psd=n"
	dns := &dmarcStatusDNS{stubDNS:stubDNS{txt:map[string][]string{
		"_dmarc.example.org":{record},
	}}}
	cases := []struct{
		name, from string
		spf SPFResult
		wantResult, wantPolicy string
	}{
		{"exact author record", "sender@example.org",SPFResult{Result:"fail"},"fail","reject"},
		{"aligned authentication", "sender@sub.example.org",SPFResult{Result:"pass",Domain:"sub.example.org"},"pass","none"},
		{"temporary SPF", "sender@sub.example.org",SPFResult{Result:"temperror"},"temperror","none"},
	}
	for _, tc := range cases {
		got := DMARCCheck(context.Background(),dns,tc.from,tc.spf,nil)
		if got.Result!=tc.wantResult || got.Policy!=tc.wantPolicy {
			t.Fatalf("%s: got %+v",tc.name,got)
		}
	}
	if len(dns.calls)!=0 { t.Fatalf("unnecessary NXDOMAIN lookups: %v",dns.calls) }
}

func TestRFC9989NonexistentPolicyEqualDispositionNeedsNoExtraDNS(t *testing.T) {
	dns:=stubDNS{txt:map[string][]string{"_dmarc.example.org":{
		"v=DMARC1; p=reject; sp=reject; np=reject; psd=n",
	}}}
	got:=DMARCCheck(context.Background(),dns,"sender@sub.example.org",SPFResult{Result:"fail"},nil)
	if got.Result!="fail" || got.Policy!="reject" {
		t.Fatalf("identical np/sp does not require NXDOMAIN check: %+v",got)
	}
}

func TestRFC9989NonexistentPolicyTestModePreservesDowngrade(t *testing.T) {
	dns:=&dmarcStatusDNS{stubDNS:stubDNS{txt:map[string][]string{
		"_dmarc.example.org":{"v=DMARC1; p=none; sp=none; np=reject; t=y; psd=n"},
	}},nx:true}
	got:=DMARCCheck(context.Background(),dns,"sender@missing.example.org",SPFResult{Result:"fail"},nil)
	if got.Result!="fail" || got.Policy!="reject" || !got.Testing || effectiveDMARCPolicy(got)!="quarantine" {
		t.Fatalf("np=t=y must downgrade reject to quarantine: %+v",got)
	}
}
