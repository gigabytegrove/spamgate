package server

import (
	"fmt"
	"net/http"
)

// Authenticated, point-in-time counters. No unauthenticated monitoring access.
// Deliberately excludes subjects, mailbox addresses, tokens and message IDs.
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	stats := s.Store.Stats("")
	counts, _ := stats["actions"].(map[string]int)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintln(w, "# HELP spamgate_history_messages Total retained scan decisions.")
	fmt.Fprintln(w, "# TYPE spamgate_history_messages gauge")
	fmt.Fprintf(w, "spamgate_history_messages %d\n", stats["total"])
	fmt.Fprintln(w, "# HELP spamgate_history_verdicts Retained decisions by action.")
	fmt.Fprintln(w, "# TYPE spamgate_history_verdicts gauge")
	for _, action := range []string{"accept", "tag", "quarantine", "reject"} {
		fmt.Fprintf(w, "spamgate_history_verdicts{action=%q} %d\n", action, counts[action])
	}
	if s.Queue != nil {
		q, e := s.Queue.Snapshot()
		if e == nil {
			fmt.Fprintln(w, "# HELP spamgate_outbox_messages Persistent delivery jobs by status.")
			fmt.Fprintln(w, "# TYPE spamgate_outbox_messages gauge")
			for _, entry := range []struct {
				name  string
				count int
			}{{"queued", q.Queued}, {"delivering", q.Delivering}, {"dead", q.Dead}} {
				fmt.Fprintf(w, "spamgate_outbox_messages{status=%q} %d\n", entry.name, entry.count)
			}
			fmt.Fprintf(w, "spamgate_outbox_bytes %d\n", q.Bytes)
		}
	}
}
