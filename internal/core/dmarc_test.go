package core

import (
	"context"
	"testing"
)

func TestDMARCAlignment(t *testing.T) {
	dns := stubDNS{txt: map[string][]string{"_dmarc.example.org": {"v=DMARC1; p=reject; aspf=s; adkim=r"}}}
	passed := DMARCCheck(context.Background(), dns, "Sender <sender@example.org>", SPFResult{Result: "pass", Domain: "mail.example.org"}, nil)
	if passed.Result != "fail" || passed.Policy != "reject" {
		t.Fatal(passed)
	}
	passed = DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "pass", Domain: "example.org"}, nil)
	if passed.Result != "pass" {
		t.Fatal(passed)
	}
	passed = DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "fail"}, []DKIMResult{{Result: "pass", Domain: "mailer.example.org"}})
	if passed.Result != "pass" {
		t.Fatal(passed)
	}
	unaligned := DMARCCheck(context.Background(), dns, "sender@example.org", SPFResult{Result: "pass", Domain: "attacker.example.net"}, []DKIMResult{{Result: "pass", Domain: "attacker.example.net"}})
	if unaligned.Result != "fail" {
		t.Fatal(unaligned)
	}
	none := DMARCCheck(context.Background(), dns, "sender@sub.example.org", SPFResult{Result: "fail"}, nil)
	if none.Result != "none" {
		t.Fatal("organization discovery must not be claimed: ", none)
	}
}
