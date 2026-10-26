package core

import (
	"fmt"
	"testing"
	"time"
)

func TestSearchHistoryPaginationPrivacyAndFilters(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		action := "accept"
		if i%2 == 0 {
			action = "reject"
		}
		m := Message{ID: ID(), Timestamp: time.Now().Add(time.Duration(i) * time.Minute), Sender: fmt.Sprintf("origin%d@example.com", i), Recipients: []string{"person@example.org"}, Subject: fmt.Sprintf("subject-%d", i), Action: action}
		if i == 7 {
			m.Recipients = []string{"private@example.org"}
		}
		if err := store.Save(m); err != nil {
			t.Fatal(err)
		}
	}
	query := HistoryQuery{Action: "reject", Limit: 2}
	first, err := store.SearchHistory(query, "person@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 5 || len(first.Items) != 2 {
		t.Fatalf("search results %+v", first)
	}
	if len(first.Items[0].Recipients) != 1 || first.Items[0].Recipients[0] != "person@example.org" {
		t.Fatal("wrong mailbox")
	}
	query.Offset = 4
	last, err := store.SearchHistory(query, "person@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if last.Total != 5 || len(last.Items) != 1 {
		t.Fatalf("pagination %+v", last)
	}
	query.Limit = 501
	if _, err = store.SearchHistory(query, ""); err == nil {
		t.Fatal("unbounded limit accepted")
	}
	query = HistoryQuery{Limit: 10, Text: "subject-7"}
	hidden, err := store.SearchHistory(query, "person@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if hidden.Total != 0 {
		t.Fatal("cross-mailbox search leak")
	}
}
