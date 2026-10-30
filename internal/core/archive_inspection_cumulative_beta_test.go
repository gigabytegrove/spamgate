package core

import (
	"archive/zip"
	"bytes"
	"fmt"
	"testing"
)

func betaNestedZIPEntries(t *testing.T, count int) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := 0; i < count; i++ {
		member, err := w.Create(fmt.Sprintf("document-%03d.txt", i))
		if err != nil { t.Fatal(err) }
		if _, err := member.Write([]byte("ordinary content")); err != nil { t.Fatal(err) }
	}
	if err := w.Close(); err != nil { t.Fatal(err) }
	return buf.Bytes()
}

// The old per-archive entry cap allowed up to 100 entries at every nested
// level, potentially expanding the inspection work exponentially. The cap
// must cover the entire recursion tree, not each ZIP independently.
func TestBetaZIPNestedGlobalEntryBudget(t *testing.T) {
	innerA := betaNestedZIPEntries(t, 60)
	innerB := betaNestedZIPEntries(t, 60)
	outer := betaZIP(t, map[string][]byte{
		"first.zip": innerA,
		"second.zip": innerB,
	})
	findings := betaZIPMessage(t, outer)
	if !betaHasSymbol(findings, "ARCHIVE_LIMIT") {
		t.Fatalf("nested ZIPs bypassed shared 100-entry budget: %+v", findings)
	}
}

func TestBetaZIPNestedOrdinaryDocumentsRemainLowRisk(t *testing.T) {
	outer := betaZIP(t, map[string][]byte{
		"first.zip": betaNestedZIPEntries(t, 10),
		"second.zip": betaNestedZIPEntries(t, 10),
		"notes.txt": []byte("ordinary documents"),
	})
	for _, finding := range betaZIPMessage(t, outer) {
		if finding.Score != 0 {
			t.Fatalf("benign nested archive falsely scored: %+v", finding)
		}
	}
}

// A nested ZIP may contain multiple compressed bombs that individually
// remain under the per-archive expansion ceiling. Declared expanded bytes
// must be charged against one shared limit before decompression.
func TestBetaZIPNestedGlobalExpansionBudget(t *testing.T) {
	bomb := betaZIP(t, map[string][]byte{
		"large-report.txt": bytes.Repeat([]byte("A"), 18<<20),
	})
	outer := betaZIP(t, map[string][]byte{
		"first.zip": bomb,
		"second.zip": bomb,
	})
	findings := betaZIPMessage(t, outer)
	foundCombined := false
	for _, finding := range findings {
		if finding.Symbol == "ARCHIVE_EXPANSION_RISK" &&
			bytes.Contains([]byte(finding.Detail), []byte("Combined nested ZIP expansion budget exceeded")) {
			foundCombined = true
		}
	}
	if !foundCombined {
		t.Fatalf("nested archive declared expansion exceeded shared budget without warning: %+v", findings)
	}
}
