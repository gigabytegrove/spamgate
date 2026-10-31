package core

import (
	"context"
	"net"
	"strings"
	"testing"
)

type stubDNS struct {
	txt map[string][]string
	ips map[string][]net.IPAddr
	mx  map[string][]*net.MX
}

func (r stubDNS) LookupTXT(_ context.Context, n string) ([]string, error) {
	if a, ok := r.txt[n]; ok {
		return a, nil
	}
	return nil, &net.DNSError{IsNotFound: true, Name: n}
}
func (r stubDNS) LookupIPAddr(_ context.Context, n string) ([]net.IPAddr, error) {
	if a, ok := r.ips[n]; ok {
		return a, nil
	}
	return nil, &net.DNSError{IsNotFound: true, Name: n}
}
func (r stubDNS) LookupMX(_ context.Context, n string) ([]*net.MX, error) {
	if a, ok := r.mx[n]; ok {
		return a, nil
	}
	return nil, &net.DNSError{IsNotFound: true, Name: n}
}
func TestSPFMechanisms(t *testing.T) {
	tests := []struct{ name, record, ip, want string }{
		{"pass", "v=spf1 ip4:203.0.113.0/24 -all", "203.0.113.1", "pass"},
		{"fail", "v=spf1 ip4:203.0.113.0/24 -all", "192.0.2.1", "fail"},
		{"softfail", "v=spf1 ~all", "203.0.113.8", "softfail"},
		{"neutral", "v=spf1 ?all", "203.0.113.8", "neutral"},
		{"IPv6", "v=spf1 ip6:2001:db8::/32 -all", "2001:db8::2", "pass"},
		{"invalid", "v=spf1 ip4:broken -all", "203.0.113.8", "permerror"},
		{"unknown", "v=spf1 invented -all", "203.0.113.8", "permerror"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := stubDNS{txt: map[string][]string{"example.org": {test.record}}}
			got := SPFCheck(context.Background(), r, test.ip, "<mailer@example.org>", "")
			if got.Result != test.want {
				t.Fatalf("got %+v, want %s", got, test.want)
			}
		})
	}
}
func TestSPFIncludeRedirectAndCycle(t *testing.T) {
	r := stubDNS{txt: map[string][]string{
		"example.org":          {"v=spf1 include:approved.example.org -all"},
		"approved.example.org": {"v=spf1 ip4:203.0.113.4 -all"},
	}}
	if got := SPFCheck(context.Background(), r, "203.0.113.4", "mailer@example.org", ""); got.Result != "pass" {
		t.Fatal(got)
	}
	r.txt["approved.example.org"] = []string{"v=spf1 include:example.org"}
	if got := SPFCheck(context.Background(), r, "203.0.113.4", "mailer@example.org", ""); got.Result != "permerror" {
		t.Fatal(got)
	}
	r.txt["example.org"] = []string{"v=spf1 -all", "v=spf1 +all"}
	if got := SPFCheck(context.Background(), r, "203.0.113.4", "mailer@example.org", ""); got.Result != "permerror" {
		t.Fatal(got)
	}
}
func TestSPFNoDataAndNoIP(t *testing.T) {
	r := stubDNS{txt: map[string][]string{"example.org": {""}}}
	if got := SPFCheck(context.Background(), r, "", "test@example.org", ""); got.Result != "none" {
		t.Fatal(got)
	}
	if got := SPFCheck(context.Background(), r, "203.0.113.4", "test@example.org", ""); got.Result != "none" {
		t.Fatal(got)
	}
	r.txt["example.org"] = []string{"v=spf1 include:nonexistent.example.org -all"}
	got := SPFCheck(context.Background(), r, "203.0.113.4", "test@example.org", "")
	if got.Result != "permerror" || !strings.Contains(got.Explanation, "no SPF policy") {
		t.Fatal(got)
	}
}
