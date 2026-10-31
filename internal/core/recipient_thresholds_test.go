package core

import (
	"context"
	"testing"
)
func TestRecipientThresholdsTransactionSafety(t *testing.T) {
	s := Settings{TagThreshold: 5, QuarantineThreshold: 10, RejectThreshold: 20}
	policies := []RecipientPolicy{
		{Mailbox: "alice@example.org", TagThreshold: 1, QuarantineThreshold: 2, RejectThreshold: 3},
		{Mailbox: "bob@example.org", TagThreshold: 1, QuarantineThreshold: 2, RejectThreshold: 3},
		{Mailbox: "carol@example.org", TagThreshold: 2, QuarantineThreshold: 4, RejectThreshold: 6},
		{Mailbox: "default@example.org", TagThreshold: 5, QuarantineThreshold: 10, RejectThreshold: 20},
	}
	for _, tc := range []struct{name string; recipients []string; source string; tag float64}{
		{"single", []string{"alice@example.org"}, "mailbox", 1},
		{"duplicates", []string{"ALICE@example.org", "alice@example.org"}, "mailbox", 1},
		{"uniform", []string{"alice@example.org", "bob@example.org"}, "mailbox_shared", 1},
		{"reversed", []string{"bob@example.org", "alice@example.org"}, "mailbox_shared", 1},
		{"conflict", []string{"alice@example.org", "carol@example.org"}, "global_multi_recipient", 5},
		{"partial", []string{"alice@example.org", "unknown@example.org"}, "global_multi_recipient", 5},
		{"same as global", []string{"default@example.org", "unknown@example.org"}, "global", 5},
		{"unknown", []string{"unknown@example.org"}, "global", 5},
		{"empty", nil, "global", 5},
	} {
		t.Run(tc.name,func(t *testing.T) {
			got:=SelectRecipientThresholds(s,policies,tc.recipients)
			if got.Source!=tc.source || got.TagThreshold!=tc.tag {t.Fatalf("selection: %+v",got)}
			if got.Source=="global_multi_recipient" && (got.QuarantineThreshold!=10 || got.RejectThreshold!=20) {t.Fatalf("partial policy escaped: %+v",got)}
		})
	}
}
func TestScannerUsesSharedRecipientThresholdSelection(t *testing.T) {
	st,err:=Open(t.TempDir());if err!=nil{t.Fatal(err)}
	if err:=st.UpdateConfig(func(c *Config)error{
		c.RecipientPolicies=[]RecipientPolicy{
			{Mailbox:"alice@example.org",TagThreshold:1,QuarantineThreshold:2,RejectThreshold:3},
			{Mailbox:"bob@example.org",TagThreshold:1,QuarantineThreshold:2,RejectThreshold:3},
			{Mailbox:"carol@example.org",TagThreshold:2,QuarantineThreshold:4,RejectThreshold:6},
		};return nil
	});err!=nil{t.Fatal(err)}
	raw:=[]byte("From: sender@example.net\r\nTo: alice@example.org\r\nDate: Fri, 30 Oct 2026 12:00:00 +0000\r\nMessage-ID: <thresholds@example.net>\r\nSubject: Ordinary notice\r\n\r\nHello.\r\n")
	for _,tc:=range []struct{recipients []string;tag float64}{
		{[]string{"alice@example.org","ALICE@example.org"},1},
		{[]string{"alice@example.org","bob@example.org"},1},
		{[]string{"alice@example.org","carol@example.org"},5},
		{[]string{"alice@example.org","unknown@example.org"},5},
	}{
		m,err:=(&Scanner{Store:st,Resolver:stubDNS{}}).Scan(context.Background(),Input{Raw:raw,Sender:"sender@example.net",Recipients:tc.recipients,Connector:"milter"})
		if err!=nil{t.Fatal(err)}
		if m.Scoring==nil||m.Scoring.TagThreshold!=tc.tag||len(m.Recipients)!=len(tc.recipients){t.Fatalf("scan policy/envelope mismatch: %+v",m)}
	}
}
