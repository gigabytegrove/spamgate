package core

import (
	"fmt"
	"testing"
	"time"
)

func TestNeuralExplicitTrainingAndPersistence(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	spam := []Finding{{Symbol: "R_SPF_FAIL", Score: 4}, {Symbol: "DMARC_FAIL", Score: 6}, {Symbol: "CONTENT_VERIFY_YOUR_ACCOUNT", Score: 2}}
	ham := []Finding{{Symbol: "R_DKIM_ALLOW", Score: -1}, {Symbol: "DMARC_PASS", Score: -1}, {Symbol: "R_SPF_ALLOW", Score: -1}}
	if got := st.ScoreNeural(spam); got.Ready {
		t.Fatal(got)
	}
	for i := 0; i < 25; i++ {
		for _, tc := range []struct {
			label    string
			features []Finding
		}{{"spam", spam}, {"ham", ham}} {
			msg := Message{ID: ID(), Timestamp: time.Now().UTC(), Subject: fmt.Sprint("confirmed-", i), Findings: tc.features}
			if err := st.Save(msg); err != nil {
				t.Fatal(err)
			}
			if _, err := st.TrainNeural(msg.ID, tc.label); err != nil {
				t.Fatal(err)
			}
			if _, err := st.TrainNeural(msg.ID, "different"); err == nil {
				t.Fatal("invalid label accepted")
			}
			again, err := st.TrainNeural(msg.ID, tc.label)
			if err != nil || again.Ham+again.Spam > 50 {
				t.Fatal(again, err)
			}
			if _, err := st.TrainNeural(msg.ID, map[string]string{"spam": "ham", "ham": "spam"}[tc.label]); err == nil {
				t.Fatal("contradictory label accepted")
			}
		}
	}
	probSpam := st.ScoreNeural(spam)
	probHam := st.ScoreNeural(ham)
	if !probSpam.Ready || probSpam.Probability <= probHam.Probability+0.5 {
		t.Fatalf("model not discriminating: spam=%+v ham=%+v", probSpam, probHam)
	}
	reopened, err := Open(st.dir)
	if err != nil {
		t.Fatal(err)
	}
	if actual := reopened.ScoreNeural(spam); !actual.Ready || actual.Probability != probSpam.Probability {
		t.Fatal(actual, probSpam)
	}
	if _, err := st.TrainNeural("unknown-id", "spam"); err == nil {
		t.Fatal("missing message accepted")
	}
	if _, err := neuralInput(nil); err == nil {
		t.Fatal("empty input accepted")
	}
	if _, err := neuralInput([]Finding{{Symbol: "NEURAL_SPAM"}, {Symbol: "FUZZY_SPAM"}}); err == nil {
		t.Fatal("feedback leak allowed")
	}
}
