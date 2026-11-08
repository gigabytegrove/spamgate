package core

import "testing"

func TestPhishingVisibleURLZeroWidthNormalization(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{"zero width space", "https://bank.\u200bexample.com", "https://bank.example.com"},
		{"zero width non joiner", "https://bank.\u200cexample.com", "https://bank.example.com"},
		{"zero width joiner", "https://bank.\u200dexample.com", "https://bank.example.com"},
		{"word joiner", "https://bank.\u2060example.com", "https://bank.example.com"},
		{"byte order mark", "\ufeffhttps://bank.example.com", "https://bank.example.com"},
		{"HTML entity", "https://bank.&#8203;example.com", "https://bank.example.com"},
		{"visible whitespace preserved", "https://bank. example.com", "https://bank. example.com"},
		{"visible newline preserved", "https://bank.\nexample.com", "https://bank.\nexample.com"},
		{"plain URL unchanged", "https://bank.example.com", "https://bank.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := phishingVisibleURLText(tc.input); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestPhishingZeroWidthURLClaims(t *testing.T) {
	cases := []struct {
		name, body string
		want int
	}{
		{"zero width hostname", `<a href="https://evil.example.net/login">https://bank.&#8203;example.com/login</a>`, 1},
		{"zero width scheme", `<a href="https://evil.example.net/login">ht&#8203;tps://bank.example.com/login</a>`, 1},
		{"zero width split inline", `<a href="https://evil.example.net/login"><span>https://bank.</span><span>&#8203;example.com</span></a>`, 1},
		{"same organization", `<a href="https://login.example.com">https://&#8203;support.example.com</a>`, 0},
		{"visible space not joined", `<a href="https://evil.example.net/login">https://bank. example.com/login</a>`, 0},
		{"normal legitimate URL", `<a href="https://bank.example.com/login">https://bank.example.com/login</a>`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coverage := &mimeCoverage{}
			got := phishingVisibleLinksWithCoverage(tc.body, coverage)
			if len(got) != tc.want || coverage.Incomplete {
				t.Fatalf("findings=%v coverage=%+v want=%d", got, coverage, tc.want)
			}
		})
	}
}

func TestPhishingZeroWidthMIMEIntegration(t *testing.T) {
	body := `<a href="https://evil.example.net/login">https://bank.&#8203;example.com/login</a>`
	got, coverage := detectPhishingLinksWithCoverage(phishingFixture("text/html", "", "", body))
	if len(got) != 1 || coverage.Incomplete {
		t.Fatalf("MIME findings=%v coverage=%+v", got, coverage)
	}
}
