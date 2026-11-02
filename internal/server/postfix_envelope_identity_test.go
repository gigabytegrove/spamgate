package server

import "testing"

func TestPostfixEnvelopeIdentityCanonicalization(t *testing.T) {
	valid := []struct{ in, key string }{
		{"User@Example.ORG", "User@example.org"},
		{"user@EXAMPLE.org", "user@example.org"},
		{"a+b@localhost", "a+b@localhost"},
		{"büro@XN--BCHER-KVA.example", "büro@xn--bcher-kva.example"},
		{"User@sub.EXAMPLE.org", "User@sub.example.org"},
	}
	for _, tc := range valid {
		if got, ok := postfixEnvelopeMailboxKey(tc.in); !ok || got != tc.key {
			t.Errorf("valid mailbox %q => %q, %v; want %q", tc.in, got, ok, tc.key)
		}
	}
	invalid := []string{"", "user", "@example.org", "user@", "user@@example.org", "a@bad..example", "a@-example.org", "a@example-.org", "a@example.org.", "a@ex_ample.org", "a@bücher.example", "a@example.org\r\nBcc:evil", "a b@example.org", "<a@example.org>", "a@exa<mple.org", "a@", "a@.", "a@x\x00.org"}
	for _, in := range invalid {
		if got, ok := postfixEnvelopeMailboxKey(in); ok {
			t.Errorf("invalid mailbox %q accepted as %q", in, got)
		}
	}
	for _, tc := range []struct {
		sender, key string
		ok          bool
	}{
		{"", "<>", true}, {"<>", "<>", true},
		{"User@Example.org", "User@example.org", true},
		{"<User@Example.org>", "User@example.org", true},
		{"<<User@Example.org>>", "", false},
		{"<>", "<>", true},
		{"<User@Example.org", "", false},
		{"User@Example.org>", "", false},
		{"< >", "", false},
	} {
		if got, ok := postfixEnvelopeSenderKey(tc.sender); ok != tc.ok || got != tc.key {
			t.Errorf("sender %q => %q, %v; want %q, %v", tc.sender, got, ok, tc.key, tc.ok)
		}
	}
}
