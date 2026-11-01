package core

import (
	"strings"
	"testing"
)

func TestPhishingInlineCSSHidden(t *testing.T) {
	for _, tc := range []struct{name, style string; hidden bool}{
		{"display none", "display:none", true},
		{"visibility hidden", "visibility : hidden", true},
		{"visibility collapse", "visibility:collapse", true},
		{"case insensitive", "DISPLAY : NONE", true},
		{"comment", "display:/*ok*/none", true},
		{"last declaration wins", "display:none; display:block", false},
		{"last declaration hides", "display:block; display:none", true},
		{"important wins", "display:none !important; display:block", true},
		{"later important wins", "display:none!important; display:block !important", false},
		{"later normal cannot override important", "display:block!important; display:none", false},
		{"whitespace important", "visibility:hidden ! important; visibility:visible", true},
		{"quoted value not property", "content:'display:none'", false},
		{"custom property", "--hidden:display:none", false},
		{"substring in value", "display:none-block", false},
		{"quoted semicolon", "content:'a;b';display:none", true},
		{"url semicolon", "background:url('a;b');display:none", true},
		{"commented declaration", "/* display:none */ display:block", false},
		{"comment after declaration", "display:none;/*display:block*/", true},
		{"invalid override", "display:none;display:foobar", true},
		{"valid visible", "display:flex;visibility:visible", false},
		{"hidden other property", "background:'visibility:hidden'", false},
		{"unterminated quote", "content:'display:none", false},
	} {
		t.Run(tc.name,func(t *testing.T){ if got:=phishingInlineCSSHidden(tc.style);got!=tc.hidden { t.Fatalf("%q: hidden=%v want %v",tc.style,got,tc.hidden) } })
	}
}

func TestPhishingCSSCascadeVisibleLinkIntegration(t *testing.T) {
	const mismatch = "<a href='https://evil.example.net'>https://bank.example.com</a>"
	for _, tc := range []struct {name, style string; want int}{
		{"hidden", "display:none", 0},
		{"overridden visible", "display:none;display:block", 1},
		{"important hidden", "display:none!important;display:block", 0},
		{"important visible", "display:none;display:block!important", 1},
		{"unrelated content", "content:'display:none'", 1},
		{"custom property", "--custom:display:none", 1},
		{"hidden visibility", "visibility:hidden", 0},
		{"encoded style colon", "display&#58;none", 0},
		{"encoded visibility colon", "visibility&#58;hidden", 0},
		{"visible visibility", "visibility:hidden;visibility:visible", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			html := "<div style=\"" + tc.style + "\">" + mismatch + "</div>"
			coverage := &mimeCoverage{}
			got := phishingVisibleLinksWithCoverage(html, coverage)
			if len(got) != tc.want || coverage.Incomplete {
				t.Fatalf("style=%q findings=%v coverage=%+v want=%d", tc.style, got, coverage, tc.want)
			}
		})
	}
}

func TestPhishingConvenienceHelperNilCoverageIsSafe(t *testing.T) {
	const mismatch = "<a href='https://evil.example.net'>https://bank.example.com</a>"
	if got := phishingVisibleLinks("<!--" + mismatch); len(got) != 0 {
		t.Fatalf("unterminated comment scored: %v", got)
	}
	if got := phishingVisibleLinks(strings.Repeat(mismatch, 60)); len(got) != 10 {
		t.Fatalf("anchor budget: got %d findings, want 10", len(got))
	}
}

func TestPhishingHTMLNestingBudget(t *testing.T) {
	const mismatch = "<a href='https://evil.example.net'>https://bank.example.com</a>"
	html := strings.Repeat("<div>", 300) + mismatch + strings.Repeat("</div>", 300)
	coverage := &mimeCoverage{}
	found := phishingVisibleLinksWithCoverage(html, coverage)
	if len(found) != 0 || !coverage.Incomplete || !strings.Contains(strings.Join(coverage.Reasons, " "), "256") {
		t.Fatalf("unbounded nesting was not reported: findings=%v coverage=%+v", found, coverage)
	}
}

func TestPhishingEncodedAriaHidden(t *testing.T) {
	const mismatch = "<a href='https://evil.example.net'>https://bank.example.com</a>"
	if got := phishingVisibleLinks("<div aria-hidden='tr&#117;e'>" + mismatch + "</div>"); len(got) != 0 {
		t.Fatalf("encoded aria-hidden attribute leaked a finding: %v", got)
	}
}
