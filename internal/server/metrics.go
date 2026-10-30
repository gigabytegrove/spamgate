package server

import (
	"fmt"
	"github.com/gigabytegrove/spamgate/internal/core"
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
	for _, action := range []string{"accept", "tag", "quarantine", "reject", "soft_reject"} {
		fmt.Fprintf(w, "spamgate_history_verdicts{action=%q} %d\n", action, counts[action])
	}
	telemetry := core.RuntimeScanTelemetry()
	fmt.Fprintln(w, "# HELP spamgate_runtime_scans_total Scan operations attempted since this SpamGate process started.")
	fmt.Fprintln(w, "# TYPE spamgate_runtime_scans_total counter")
	fmt.Fprintf(w, "spamgate_runtime_scans_total %d\n", telemetry.Total)
	fmt.Fprintln(w, "# HELP spamgate_runtime_scan_errors_total Scanner operations that returned an error.")
	fmt.Fprintln(w, "# TYPE spamgate_runtime_scan_errors_total counter")
	fmt.Fprintf(w, "spamgate_runtime_scan_errors_total %d\n", telemetry.Errors)
	fmt.Fprintln(w, "# HELP spamgate_runtime_scan_actions_total Completed scan operations by decision.")
	fmt.Fprintln(w, "# TYPE spamgate_runtime_scan_actions_total counter")
	for _, action := range []string{"accept", "tag", "quarantine", "reject", "soft_reject", "error", "other"} {
		fmt.Fprintf(w, "spamgate_runtime_scan_actions_total{action=%q} %d\n", action, telemetry.ByAction[action])
	}
	fmt.Fprintln(w, "# HELP spamgate_runtime_scan_connector_total Scan operations by connector.")
	fmt.Fprintln(w, "# TYPE spamgate_runtime_scan_connector_total counter")
	for _, connector := range []string{"milter", "smtp", "rspamd", "rspamd-http", "controller", "simulation", "other"} {
		fmt.Fprintf(w, "spamgate_runtime_scan_connector_total{connector=%q} %d\n", connector, telemetry.ByConnector[connector])
	}
	fmt.Fprintln(w, "# HELP spamgate_runtime_scan_duration_seconds Actual scanner wall-clock time.")
	fmt.Fprintln(w, "# TYPE spamgate_runtime_scan_duration_seconds histogram")
	for i, label := range []string{"0.005", "0.02", "0.1", "0.25", "1", "5", "+Inf"} {
		fmt.Fprintf(w, "spamgate_runtime_scan_duration_seconds_bucket{le=%q} %d\n", label, telemetry.DurationBuckets[i])
	}
	fmt.Fprintf(w, "spamgate_runtime_scan_duration_seconds_sum %.6f\n", telemetry.DurationSecondsSum)
	fmt.Fprintf(w, "spamgate_runtime_scan_duration_seconds_count %d\n", telemetry.Total)
	fmt.Fprintln(w, "# HELP spamgate_outbox_snapshot_available Whether the durable outbox snapshot could be read; zero also means the outbox is disabled.")
	fmt.Fprintln(w, "# TYPE spamgate_outbox_snapshot_available gauge")
	fmt.Fprintln(w, "# HELP spamgate_outbox_snapshot_error Whether the enabled durable outbox failed its integrity/readability check.")
	fmt.Fprintln(w, "# TYPE spamgate_outbox_snapshot_error gauge")
	if s.Queue == nil {
		fmt.Fprintln(w, "spamgate_outbox_snapshot_available 0")
		fmt.Fprintln(w, "spamgate_outbox_snapshot_error 0")
		return
	}
	q, e := s.Queue.Snapshot()
	if e != nil {
		// Never silently omit metrics and make a corrupt queue appear empty.
		// The detailed error remains in authenticated operations diagnostics.
		fmt.Fprintln(w, "spamgate_outbox_snapshot_available 0")
		fmt.Fprintln(w, "spamgate_outbox_snapshot_error 1")
		return
	}
	fmt.Fprintln(w, "spamgate_outbox_snapshot_available 1")
	fmt.Fprintln(w, "spamgate_outbox_snapshot_error 0")
	fmt.Fprintln(w, "# HELP spamgate_outbox_messages Persistent delivery jobs by status.")
	fmt.Fprintln(w, "# TYPE spamgate_outbox_messages gauge")
	for _, entry := range []struct {
		name string
		count int
	}{{"queued", q.Queued}, {"delivering", q.Delivering}, {"dead", q.Dead}} {
		fmt.Fprintf(w, "spamgate_outbox_messages{status=%q} %d\n", entry.name, entry.count)
	}
	fmt.Fprintf(w, "spamgate_outbox_bytes %d\n", q.Bytes)
}
