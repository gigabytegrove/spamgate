package core

import (
	"strings"
	"testing"
)

const phishingFakeAnchor = "<a href='https://evil.example.net/login'>https://bank.example.com/login</a>"

func TestPhishingAttributeAnchorImpersonation(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want int
	}{
		{"data template", "<div data-template=\"" + phishingFakeAnchor + "\">Safe</div>", 0},
		{"title attribute", "<div title=\"" + phishingFakeAnchor + "\">Safe</div>", 0},
		{"aria label", "<p aria-label=\"" + phishingFakeAnchor + "\">Safe</p>", 0},
		{"single quoted attribute", "<div data-template='" + strings.ReplaceAll(phishingFakeAnchor, "'", "\"") + "'>Safe</div>", 0},
		{"real anchor with fake title", "<a href='https://bank.example.com' title=\"" + phishingFakeAnchor + "\">https://bank.example.com</a>", 0},
		{"fake plus real", "<div data-template=\"" + phishingFakeAnchor + "\">Safe</div>" + phishingFakeAnchor, 1},
		{"quoted greater than", "<div title=\"x > " + phishingFakeAnchor + "\">Safe</div>", 0},
		{"nested visible span", "<a href='https://evil.example.net'><span>https://bank.example.com</span></a>", 1},
		{"entity URL text", "<a href='https://evil.example.net'>https:&#47;&#47;bank.example.com</a>", 1},
		{"nested anchors separate", "<a href='https://evil.example.net'>https://bank.example.com<a href='https://bank.example.com'>https://bank.example.com</a></a>", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coverage := &mimeCoverage{}
			got := phishingVisibleLinksWithCoverage(tc.body, coverage)
			if len(got) != tc.want || coverage.Incomplete {
				t.Fatalf("findings=%v coverage=%+v want=%d", got, coverage, tc.want)
			}
		})
	}
}

func TestPhishingAnchorTokenizerLimits(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want int
		incomplete bool
	}{
		{"unclosed anchor", "<a href='https://evil.example.net'>https://bank.example.com", 0, true},
		{"51 anchors", strings.Repeat(phishingFakeAnchor, 51), 10, true},
		{"oversized text", "<a href='https://evil.example.net'>" + strings.Repeat("a", 4097) + "</a>", 0, true},
		{"60 fake anchors in attribute", "<div title=\"" + strings.Repeat(phishingFakeAnchor, 60) + "\">Safe</div>", 0, false},
		{"script followed by real", "<script>" + phishingFakeAnchor + "</script>" + phishingFakeAnchor, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coverage := &mimeCoverage{}
			got := phishingVisibleLinksWithCoverage(tc.body, coverage)
			if len(got) != tc.want || coverage.Incomplete != tc.incomplete {
				t.Fatalf("findings=%v coverage=%+v want=%d incomplete=%v", got, coverage, tc.want, tc.incomplete)
			}
		})
	}
}

func TestPhishingFakeAnchorMIMEIntegration(t *testing.T) {
	body := "<div data-template=\"" + phishingFakeAnchor + "\">Safe</div>"
	got, coverage := detectPhishingLinksWithCoverage(phishingFixture("text/html", "", "", body))
	if len(got) != 0 || coverage.Incomplete {
		t.Fatalf("non-clickable MIME attribute was scored: %v %+v", got, coverage)
	}
}

func TestPhishingAnchorClaimHardCap(t *testing.T) {
	for _, tc := range []struct {
		name string
		count int
		wantIncomplete bool
	}{
		{"exactly 50", 50, false},
		{"51st", 51, true},
		{"1000 anchors", 1000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coverage := &mimeCoverage{}
			claims := phishingAnchorClaims(strings.Repeat(phishingFakeAnchor, tc.count), coverage)
			want := tc.count
			if want > 50 {
				want = 50
			}
			if len(claims) != want || coverage.Incomplete != tc.wantIncomplete {
				t.Fatalf("claims=%d coverage=%+v want=%d incomplete=%v", len(claims), coverage, want, tc.wantIncomplete)
			}
			for _, claim := range claims {
				if claim.href != "https://evil.example.net/login" || claim.text != "https://bank.example.com/login" {
					t.Fatalf("corrupted bounded claim: %+v", claim)
				}
			}
		})
	}
}
