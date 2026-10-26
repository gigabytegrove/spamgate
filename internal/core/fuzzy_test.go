package core

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func fuzzyMail(text string) []byte {
	return []byte("From: sender@example.org\r\nTo: inbox@example.org\r\nSubject: important quarterly report\r\nDate: Mon, 26 Oct 2026 09:00:00 +0000\r\n\r\n" + text + "\r\n")
}
func TestFuzzyLifecycleAndSimilarity(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	text := "Urgent verification of account details requires special attention to security of electronic messages. Verify the account with the designated security office in writing today. Our system has detected unusual transactions and sends this warning as a mandatory notification for review."
	raw := fuzzyMail(text)
	e, err := st.TrainFuzzy(raw, "spam")
	if err != nil {
		t.Fatal(err)
	}
	if e.Label != "spam" || e.ID == "" {
		t.Fatal(e)
	}
	repeat, err := st.TrainFuzzy(raw, "spam")
	if err != nil || e.ID != repeat.ID {
		t.Fatalf("idempotency %v %v", repeat, err)
	}
	if _, err = st.TrainFuzzy(raw, "ham"); err == nil {
		t.Fatal("contradictory label accepted")
	}
	got, err := st.ScoreFuzzy(raw)
	if err != nil || !got.Matched || got.Distance != 0 || got.Label != "spam" {
		t.Fatalf("exact match %+v %v", got, err)
	}
	edited := fuzzyMail(strings.Replace(text, "designated security office", "qualified security office", 1))
	got, err = st.ScoreFuzzy(edited)
	if err != nil || !got.Matched || got.Label != "spam" {
		t.Fatalf("edited match %+v %v", got, err)
	}
	different := fuzzyMail("Our local gardening group invites neighbors to the garden. We will plant tomatoes and cucumbers in raised beds this Saturday morning. The greenhouse will have seedlings ready for everyone who attends. Bring gardening gloves and wear comfortable shoes. We will enjoy a lovely picnic lunch afterwards.")
	got, err = st.ScoreFuzzy(different)
	if err != nil || got.Matched {
		t.Fatalf("false positive %+v %v", got, err)
	}
	if stats := st.FuzzyStats(); stats.Total != 1 || stats.Spam != 1 {
		t.Fatal(stats)
	}
	reopened, err := Open(st.dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err = reopened.ScoreFuzzy(raw)
	if err != nil || !got.Matched {
		t.Fatalf("persistence %+v %v", got, err)
	}
	if err = reopened.DeleteFuzzy(e.ID); err != nil {
		t.Fatal(err)
	}
	if err = reopened.DeleteFuzzy(e.ID); err == nil {
		t.Fatal("duplicate delete accepted")
	}
	got, err = reopened.ScoreFuzzy(raw)
	if err != nil || got.Matched {
		t.Fatalf("deletion %+v %v", got, err)
	}
	if _, err = reopened.TrainFuzzy(raw, "invalid"); err == nil {
		t.Fatal("invalid label")
	}
	if _, _, err = fuzzyFingerprint(fuzzyMail("hello")); err == nil {
		t.Fatal("short sample accepted")
	}
}
func TestFuzzyExpirationAndCapacity(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	text := "This large insurance policy change notice requires updated signatures and account verification within the current period. Please compare the latest premium payments with the insurer records before making any adjustments to the policy. The attached billing statement is available upon request through the customer service support department."
	raw := fuzzyMail(text)
	e, err := st.TrainFuzzy(raw, "spam")
	if err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	st.fuzzy[0].Created = time.Now().Add(-91 * 24 * time.Hour)
	st.mu.Unlock()
	if stats := st.FuzzyStats(); stats.Total != 0 {
		t.Fatal(stats)
	}
	if got, err := st.ScoreFuzzy(raw); err != nil || got.Matched {
		t.Fatal(got, err)
	}
	next, err := st.TrainFuzzy(raw, "ham")
	if err != nil || next.ID == e.ID {
		t.Fatal(next, err)
	}
	for _, count := range []int{0, 1, 2} {
		if count > 0 { // ensure normalization tolerates varying line lengths
			_, _, err := fuzzyFingerprint(fuzzyMail(fmt.Sprintf("Unique header %d. %s", count, text)))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
