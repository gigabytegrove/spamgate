package core

import (
	"context"
	"net"
	"testing"
)

func TestDMARCOrganizationalDomainAndPrivateSuffix(t *testing.T) {
	cases := []struct{ domain, org string }{
		{"a.b.example.com", "example.com"},
		{"news.service.example.co.uk", "example.co.uk"},
		{"tenant.github.io", "tenant.github.io"},
		{"other.tenant.github.io", "tenant.github.io"},
		{"a.example.com", "example.com"},
		{"co.uk", ""},
		{"github.io", ""},
		{"www.city.kawasaki.jp", "city.kawasaki.jp"},
	}
	for _, tc := range cases {
		if org := organizationalDomain(tc.domain); org != tc.org {
			t.Errorf("organizationalDomain(%q)=%q, want %q", tc.domain, org, tc.org)
		}
	}
	if !dmarcAligned("send.example.com", "newsletter.example.com", "r") {
		t.Fatal("two authenticated identifiers in same organizational domain should align")
	}
	if dmarcAligned("attacker.github.io", "victim.github.io", "r") {
		t.Fatal("cross-tenant hosted domains must not align")
	}
	if dmarcAligned("other.example.co.uk", "sender.another.co.uk", "r") {
		t.Fatal("different co.uk organizational domains must not align")
	}
	if dmarcAligned("mail.example.com", "example.com", "s") {
		t.Fatal("strict alignment must be exact")
	}
}

func TestDMARCPolicyFallbackSubdomainAndTransientDNS(t *testing.T) {
	resolver := stubDNS{txt: map[string][]string{"_dmarc.example.co.uk": {"v=DMARC1; p=reject; sp=quarantine; adkim=r; aspf=r"}}}
	from := "receipts@delivery.example.co.uk"
	good := DMARCCheck(context.Background(), resolver, from, SPFResult{Result: "pass", Domain: "mx.example.co.uk"}, nil)
	if good.Result != "pass" || good.Policy != "quarantine" {
		t.Fatalf("relaxed org alignment / inherited sp: %+v", good)
	}
	failing := DMARCCheck(context.Background(), resolver, from, SPFResult{Result: "fail", Domain: "bad.example.net"}, nil)
	if failing.Result != "fail" || failing.Policy != "quarantine" {
		t.Fatalf("failed inherited policy: %+v", failing)
	}
	temp := DMARCCheck(context.Background(), resolver, from, SPFResult{Result: "temperror"}, nil)
	if temp.Result != "temperror" {
		t.Fatalf("transient SPF incorrectly penalized as DMARC failure: %+v", temp)
	}
	temp = DMARCCheck(context.Background(), resolver, from, SPFResult{Result: "fail"}, []DKIMResult{{Result: "temperror", Domain: "example.co.uk"}})
	if temp.Result != "temperror" {
		t.Fatalf("transient DKIM incorrectly penalized: %+v", temp)
	}
	// No policy from a different private hosting tenant can be inherited.
	other := DMARCCheck(context.Background(), resolver, "from@x.github.io", SPFResult{Result: "fail"}, nil)
	if other.Result != "none" {
		t.Fatalf("must not derive policy from other tenant: %+v", other)
	}
}

func TestSPFAddressCIDRForAAndMX(t *testing.T) {
	dns := stubDNS{
		txt: map[string][]string{
			"a.test.example":       {"v=spf1 a:out.test.example/24 -all"},
			"mx.test.example":      {"v=spf1 mx/24 -all"},
			"v6.test.example":      {"v=spf1 a:ipv6.test.example//64 -all"},
			"invalid.test.example": {"v=spf1 a:out.test.example/50 -all"},
		},
		ips: map[string][]net.IPAddr{
			"out.test.example":  {{IP: net.ParseIP("192.0.2.25")}},
			"mx1.test.example":  {{IP: net.ParseIP("198.51.100.19")}},
			"ipv6.test.example": {{IP: net.ParseIP("2001:db8:9::1")}},
		},
		mx: map[string][]*net.MX{"mx.test.example": {{Host: "mx1.test.example"}}},
	}
	cases := []struct{ ip, domain, want string }{
		{"192.0.2.201", "a.test.example", "pass"},
		{"192.0.3.201", "a.test.example", "fail"},
		{"198.51.100.200", "mx.test.example", "pass"},
		{"2001:db8:9::beef", "v6.test.example", "pass"},
		{"2001:db8:10::1", "v6.test.example", "fail"},
		{"192.0.2.21", "invalid.test.example", "permerror"},
	}
	for _, c := range cases {
		got := SPFCheck(context.Background(), dns, c.ip, "test@"+c.domain, "")
		if got.Result != c.want {
			t.Errorf("SPF %s %s: got %+v want %s", c.ip, c.domain, got, c.want)
		}
	}
}
