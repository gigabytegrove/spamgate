package core

import (
	"os"
	"path/filepath"
	"testing"
)

func bayesExample(subject, body string) []byte {
	return []byte("From: sender@example.org\r\nDate: Mon, 26 Oct 2026 14:00:00 +0000\r\nSubject: " + subject + "\r\n\r\n" + body + "\r\n")
}
func TestBayesTrainingPersistenceAndReadiness(t *testing.T) {
	path := t.TempDir()
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if stats := st.BayesStats(); stats.Ready || stats.Ham != 0 || stats.Spam != 0 {
		t.Fatal(stats)
	}
	if _, err := st.TrainBayes(bayesExample("short", "no"), "ham"); err == nil {
		t.Fatal("accepted too-short sample")
	}
	for i := 0; i < 15; i++ {
		if _, err := st.TrainBayes(bayesExample("Important account validation", "Urgent verify password click confirm account security action immediate"), "spam"); err != nil {
			t.Fatal(err)
		}
		if _, err := st.TrainBayes(bayesExample("Meeting and family", "Friends welcome to dinner weekend garden picnic baked food social"), "ham"); err != nil {
			t.Fatal(err)
		}
	}
	stats := st.BayesStats()
	if !stats.Ready || stats.Spam != 15 || stats.Ham != 15 || stats.Terms < 10 {
		t.Fatal(stats)
	}
	score, err := st.ScoreBayes(bayesExample("verify password", "Urgent verify password confirm account security"))
	if err != nil || score.Probability < 0.95 {
		t.Fatalf("spam score %+v err=%v", score, err)
	}
	score, err = st.ScoreBayes(bayesExample("friends dinner", "Friends welcome to dinner weekend garden picnic"))
	if err != nil || score.Probability > 0.05 {
		t.Fatalf("ham score %+v err=%v", score, err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.BayesStats().Spam != 15 || reopened.BayesStats().Ham != 15 {
		t.Fatal("not persisted")
	}
	if _, err := os.Stat(filepath.Join(path, "bayes.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.TrainBayes(bayesExample("test", "This sample contains many human readable unique words"), "wrong"); err == nil {
		t.Fatal("invalid label accepted")
	}
}
