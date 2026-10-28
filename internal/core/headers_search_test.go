package core

import (
	"testing"
	"time"
)

func TestSearchFindsQueueIDDetectorAndClientIP(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	m := Message{ID: ID(), Timestamp: time.Now(), Sender: "sender@example.net", Recipients: []string{"alice@example.net", "bob@example.org"}, MTAQueueID: "ABCD12345", ClientIP: "192.0.2.19", Connector: "milter", Action: "quarantine", Findings: []Finding{{Symbol: "DMARC_FAIL", Source: "auth/dmarc", Detail: "unaligned domains", Score: 6}}}
	if err = st.Save(m); err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"abcd12345", "dmarc_fail", "unaligned domains", "192.0.2.19", "milter"} {
		r, err := st.SearchHistory(HistoryQuery{Text: needle, Limit: 10}, "")
		if err != nil || r.Total != 1 {
			t.Fatalf("search %q failed: %+v %v", needle, r, err)
		}
	}
	r, err := st.SearchHistory(HistoryQuery{Text: "bob@example.org", Limit: 10}, "alice@example.net")
	if err != nil || r.Total != 0 {
		t.Fatal("search disclosed a co-recipient")
	}
}
