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

func TestSearchHistoryDeferredVerdictsRespectMailboxIsolation(t *testing.T) {
	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		id, action, mailbox string
	}{
		{"deferred-alice", "soft_reject", "alice@example.org"},
		{"deferred-bob", "soft_reject", "bob@example.org"},
		{"accepted-alice", "accept", "alice@example.org"},
	} {
		if err := store.Save(Message{
			ID: item.id, Timestamp: time.Now(), Sender: "sender@example.net",
			Recipients: []string{item.mailbox}, Subject: item.id, Action: item.action,
		}); err != nil {
			t.Fatal(err)
		}
	}
	query := HistoryQuery{Action: "soft_reject", Limit: 50}
	all, err := store.SearchHistory(query, "")
	if err != nil {
		t.Fatalf("deferred verdict should be a supported action: %v", err)
	}
	if all.Total != 2 || len(all.Items) != 2 {
		t.Fatalf("unexpected global deferred totals: %+v", all)
	}
	alice, err := store.SearchHistory(query, "alice@example.org")
	if err != nil {
		t.Fatal(err)
	}
	if alice.Total != 1 || len(alice.Items) != 1 || alice.Items[0].ID != "deferred-alice" {
		t.Fatalf("mailbox data leakage or invalid deferred filtering: %+v", alice)
	}
	if len(alice.Items[0].Recipients) != 1 || alice.Items[0].Recipients[0] != "alice@example.org" {
		t.Fatalf("unexpected recipient exposure: %+v", alice.Items[0].Recipients)
	}
	if _, err := store.SearchHistory(HistoryQuery{Action: "invented", Limit: 50}, ""); err == nil {
		t.Fatal("invalid actions must not bypass search validation")
	}
}
