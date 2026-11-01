package core

import (
	"strings"
	"testing"
)

func TestPhishingVisibilitySuppressesNonRenderedURLClaims(t *testing.T) {
	const mismatch = `<a href="https://evil.example.net">https://bank.example.com</a>`
	for _, tc := range []struct {
		name, html string
		want, incomplete bool
	}{
		{"visible", mismatch, true, false},
		{"comment", "<!-- "+mismatch+" -->", false, false},
		{"script", "<script>var a='"+mismatch+"';</script>", false, false},
		{"script quoted greater than", "<script title=\"1 > 0\">"+mismatch+"</script>", false, false},
		{"style", "<style>"+mismatch+"</style>", false, false},
		{"template", "<template>"+mismatch+"</template>", false, false},
		{"nested template", "<template><template>"+mismatch+"</template>"+mismatch+"</template>", false, false},
		{"textarea", "<textarea>"+mismatch+"</textarea>", false, false},
		{"head", "<head>"+mismatch+"</head>", false, false},
		{"noscript", "<noscript>"+mismatch+"</noscript>", false, false},
		{"hidden", "<div hidden>"+mismatch+"</div>", false, false},
		{"hidden false still hidden", "<div hidden=\"false\">"+mismatch+"</div>", false, false},
		{"inert", "<div inert>"+mismatch+"</div>", false, false},
		{"aria hidden", "<div aria-hidden=\"true\">"+mismatch+"</div>", false, false},
		{"display none", "<div style=\"display: none\">"+mismatch+"</div>", false, false},
		{"visibility hidden", "<span style='visibility : hidden'>"+mismatch+"</span>", false, false},
		{"nested hidden", "<div hidden><span>"+mismatch+"</span></div>", false, false},
		{"visible sibling", "<div hidden>"+mismatch+"</div>"+mismatch, true, false},
		{"aria false", "<div aria-hidden=\"false\">"+mismatch+"</div>", true, false},
		{"inline greater than", "<a title=\"1 > 0\" href=\"https://evil.example.net\">https://bank.example.com</a>", true, false},
		{"unterminated comment", "<!--"+mismatch, false, true},
		{"unterminated script", "<script>"+mismatch, false, true},
		{"unterminated quoted tag", "<div title=\"unterminated >"+mismatch, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coverage := &mimeCoverage{}
			rendered := phishingRenderedHTML(tc.html, coverage)
			got := phishingVisibleLinksWithCoverage(tc.html, coverage)
			visible := len(got) == 1
			if visible != tc.want || coverage.Incomplete != tc.incomplete {
				t.Fatalf("findings=%v rendered=%q coverage=%+v; want visible=%v incomplete=%v", got, rendered, coverage, tc.want, tc.incomplete)
			}
		})
	}
}

func TestPhishingHiddenAnchorTextCannotImpersonateVisibleURL(t *testing.T) {
	const html = `<a href="https://evil.example.net"><span hidden>https://bank.example.com</span>Read more</a>`
	if found := phishingVisibleLinks(html); len(found) != 0 {
		t.Fatalf("hidden anchor text scored as visible impersonation: %+v", found)
	}
}

func TestPhishingBooleanHrefDuplicateDoesNotScore(t *testing.T) {
	const html = `<a href href="https://evil.example.net">https://bank.example.com</a>`
	if href := anchorHref(` href href="https://evil.example.net"`); href != "" {
		t.Fatalf("browser's first boolean href was ignored: %q", href)
	}
	if found := phishingVisibleLinks(html); len(found) != 0 {
		t.Fatalf("duplicate href created a false-positive mismatch: %+v", found)
	}
}

func TestPhishingMalformedHiddenHTMLProducesZeroScoreCoverage(t *testing.T) {
	raw := phishingFixture("text/html", "", "", "<script><a href=\"https://evil.example.net\">https://bank.example.com</a>")
	found, coverage := detectPhishingLinksWithCoverage(raw)
	if len(found) != 0 || !coverage.Incomplete || !strings.Contains(strings.Join(coverage.Reasons, " "), "Unterminated") {
		t.Fatalf("malformed hidden HTML was scored or unreported: findings=%v coverage=%+v", found, coverage)
	}
}

func TestPhishingVisibilityLargeRawTextSequence(t *testing.T) {
	const mismatch = `<a href="https://evil.example.net">https://bank.example.com</a>`
	body := strings.Repeat("<SCRIPT>"+mismatch+"</SCRIPT>", 3000) + mismatch
	coverage := &mimeCoverage{}
	got := phishingVisibleLinksWithCoverage(body, coverage)
	if coverage.Incomplete || len(got) != 1 {
		t.Fatalf("raw-text sequence leaked hidden links or reported incomplete: findings=%+v coverage=%+v", got, coverage)
	}
}
