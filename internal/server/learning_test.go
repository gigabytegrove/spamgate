package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestLearningAdminIsolationAndAPI(t *testing.T) {
	st, e := core.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	adminKey, adminHash, e := core.MakeToken()
	if e != nil {
		t.Fatal(e)
	}
	scanKey, scanHash, e := core.MakeToken()
	if e != nil {
		t.Fatal(e)
	}
	if e = st.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Tokens = []core.Token{{Name: "admin", Scope: "admin", Hash: adminHash}, {Name: "scanner", Scope: "scan", Hash: scanHash}}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	record := core.Message{ID: core.ID(), Timestamp: time.Now().UTC(), Findings: []core.Finding{{Symbol: "DMARC_FAIL", Source: "auth/dmarc", Score: 5}, {Symbol: "R_SPF_FAIL", Source: "auth/spf", Score: 4}}}
	if e = st.Save(record); e != nil {
		t.Fatal(e)
	}
	ts := httptest.NewServer(New(st, nil).Router())
	defer ts.Close()
	call := func(method, path, key string, body []byte) (int, []byte) {
		t.Helper()
		r, e := http.NewRequest(method, ts.URL+path, bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		if key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		res, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b := make([]byte, 0, 1024)
		tmp := make([]byte, 4096)
		for {
			n, err := res.Body.Read(tmp)
			b = append(b, tmp[:n]...)
			if err != nil {
				break
			}
		}
		return res.StatusCode, b
	}
	eml := []byte("From: test@example.org\r\nSubject: Important transaction verification\r\nDate: Mon, 26 Oct 2026 09:00:00 +0000\r\n\r\nOur support representative must review the transaction record and check every detail of your subscription. The account holder has requested an immediate payment review for outstanding invoice amounts. All corresponding records must be verified with an authorized department before approval.")
	for _, path := range []string{"/api/v1/fuzzy/stats", "/api/v1/fuzzy/entries", "/api/v1/neural/stats"} {
		if code, _ := call("GET", path, "", nil); code != 401 {
			t.Fatalf("anonymous access %s %d", path, code)
		}
		if code, _ := call("GET", path, scanKey, nil); code != 403 {
			t.Fatalf("scan key access %s %d", path, code)
		}
		if code, _ := call("GET", path, adminKey, nil); code != 200 {
			t.Fatalf("admin read %s %d", path, code)
		}
	}
	for _, path := range []string{"/api/v1/fuzzy/train?label=spam", "/api/v1/neural/train/" + record.ID + "?label=spam"} {
		if code, _ := call("POST", path, scanKey, eml); code != 403 {
			t.Fatalf("scan key write %s %d", path, code)
		}
	}
	code, b := call("POST", "/api/v1/fuzzy/train?label=spam", adminKey, eml)
	if code != 200 {
		t.Fatalf("fuzzy training %d: %s", code, b)
	}
	var entry core.FuzzyEntry
	if e = json.Unmarshal(b, &entry); e != nil || entry.ID == "" {
		t.Fatal(string(b), e)
	}
	code, b = call("POST", "/api/v1/neural/train/"+record.ID+"?label=spam", adminKey, nil)
	if code != 200 {
		t.Fatalf("neural training %d %s", code, b)
	}
	code, b = call("DELETE", "/api/v1/fuzzy/entries/"+entry.ID, adminKey, nil)
	if code != 200 {
		t.Fatalf("fuzzy delete %d %s", code, b)
	}
	if stats := st.FuzzyStats(); stats.Total != 0 {
		t.Fatal(stats)
	}
	if stats := st.NeuralStats(); stats.Spam != 1 {
		t.Fatal(stats)
	}
}
