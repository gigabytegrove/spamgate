package server

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestPolicyPreviewExactBoundariesAndRecipientFallback(t *testing.T) {
	p := policyPreviewRequest{TagThreshold: 4, QuarantineThreshold: 8, RejectThreshold: 15, Limit: 50}
	rps := []core.RecipientPolicy{{Mailbox: "one@example.org", TagThreshold: 1, QuarantineThreshold: 2, RejectThreshold: 3}}
	for _, tc := range []struct {
		score float64
		want  string
	}{{-1, "accept"}, {3.99, "accept"}, {4, "tag"}, {7.999, "tag"}, {8, "quarantine"}, {14.99, "quarantine"}, {15, "reject"}} {
		item := previewOne(core.Message{ID: "case", Score: tc.score, Action: "accept", Recipients: []string{"other@example.org"}}, p, rps)
		if item.HypotheticalAction != tc.want {
			t.Fatalf("score %f: %s != %s", tc.score, item.HypotheticalAction, tc.want)
		}
	}
	single := previewOne(core.Message{Score: 4, Action: "tag", Recipients: []string{"ONE@example.org"}}, p, rps)
	if single.HypotheticalAction != "reject" || single.PolicySource != "mailbox" {
		t.Fatalf("mailbox thresholds not applied: %+v", single)
	}
	multi := previewOne(core.Message{Score: 4, Action: "tag", Recipients: []string{"one@example.org", "other@example.org"}}, p, rps)
	if multi.HypotheticalAction != "tag" || multi.PolicySource != "global_multi_recipient" {
		t.Fatalf("unsafe per-recipient split: %+v", multi)
	}
	forced := previewOne(core.Message{Score: 1, Action: "reject", Scoring: &core.ScoringTrace{ForcedAction: "reject"}}, p, rps)
	if forced.HypotheticalAction != "reject" || !forced.Forced || forced.Changed {
		t.Fatal("historical forced rejection lost")
	}
}

func TestPolicyPreviewRejectsInvalidAndDuplicatePolicies(t *testing.T) {
	good := policyPreviewRequest{TagThreshold: 4, QuarantineThreshold: 8, RejectThreshold: 15, Limit: 10}
	if err := validatePreview(good); err != nil {
		t.Fatal(err)
	}
	for _, x := range []policyPreviewRequest{
		{TagThreshold: 8, QuarantineThreshold: 8, RejectThreshold: 15, Limit: 10},
		{TagThreshold: math.NaN(), QuarantineThreshold: 8, RejectThreshold: 15, Limit: 10},
		{TagThreshold: 4, QuarantineThreshold: 8, RejectThreshold: math.Inf(1), Limit: 10},
		{TagThreshold: 4, QuarantineThreshold: 8, RejectThreshold: 15, Limit: 501},
	} {
		if validatePreview(x) == nil {
			t.Fatalf("invalid policy accepted: %+v", x)
		}
	}
	rp := []core.RecipientPolicy{{Mailbox: "ONE@example.org", TagThreshold: 1, QuarantineThreshold: 2, RejectThreshold: 3}, {Mailbox: "one@example.org", TagThreshold: 1, QuarantineThreshold: 2, RejectThreshold: 3}}
	good.RecipientPolicies = &rp
	if validatePreview(good) == nil {
		t.Fatal("duplicate mailbox policies accepted")
	}
}

func TestPolicyPreviewHTTPIsAdminOnlyReadOnlyAndBounded(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	token, hash, err := core.MakeToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Tokens = []core.Token{{Name: "ops", Hash: hash, Scope: "admin", Created: time.Now()}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	message := core.Message{ID: core.ID(), Timestamp: time.Now().UTC(), Sender: "sender@example.org", Recipients: []string{"alice@example.org"}, Action: "tag", Score: 6}
	if err := store.Save(message); err != nil {
		t.Fatal(err)
	}
	before := store.Config()
	router := New(store, nil).Router()
	body := []byte(`{"tag_threshold":7,"quarantine_threshold":12,"reject_threshold":20,"limit":20}`)
	request := func(auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/policy/preview", bytes.NewReader(body))
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := request(""); w.Code != 401 {
		t.Fatalf("public access: %d", w.Code)
	}
	w := request(token)
	if w.Code != 200 {
		t.Fatalf("preview: %d %s", w.Code, w.Body.String())
	}
	var result struct {
		Simulation bool                `json:"simulation"`
		Persisted  bool                `json:"persisted"`
		Totals     policyPreviewTotals `json:"totals"`
		Items      []policyPreviewItem `json:"items"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Simulation || result.Persisted || result.Totals.Changed != 1 || len(result.Items) != 1 || result.Items[0].HypotheticalAction != "accept" {
		t.Fatalf("unexpected preview: %+v", result)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("alice@example.org")) || bytes.Contains(w.Body.Bytes(), []byte("sender@example.org")) {
		t.Fatal("preview leaks addresses")
	}
	if store.Config().Settings.TagThreshold != before.Settings.TagThreshold {
		t.Fatal("preview mutated policy")
	}
	persisted, ok := store.Get(message.ID)
	if !ok || persisted.Action != "tag" {
		t.Fatal("preview mutated historical verdict")
	}
}
