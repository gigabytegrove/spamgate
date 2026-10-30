package server

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const evidenceTailLimit int64 = 4 << 20
const evidenceMaxEvents = 100

// Require a real syslog/journal prefix and a Postfix process at the expected
// position. An attacker-controlled warning string containing "postfix/smtp"
// must not be mistaken for independent delivery evidence.
var postfixEvidenceLine = regexp.MustCompile(`^(?:[A-Z][a-z]{2} +[0-9]{1,2}(?: +[0-9]{2}:[0-9]{2}:[0-9]{2})?|[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+) +[^ ]+ +postfix/([a-zA-Z0-9_-]+)\[[0-9]+\]: ([A-Za-z0-9]{1,32}): (.*)package server

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const evidenceTailLimit int64 = 4 << 20
const evidenceMaxEvents = 100

)
var postfixStatus = regexp.MustCompile(`\bstatus=(sent|deferred|bounced|expired|hold)\b`)

type deliveryEvidenceEvent struct {
	Line   string `json:"line"`
	Status string `json:"status,omitempty"`
}

// This deliberately reads only the explicitly configured local log file. It
// does not run shell commands, follow request-supplied paths or accept an ID
// other than the exact queue ID recorded for this scan. An MTA queue ID is
// evidence of correlation, not proof of final mailbox delivery.
func (s *Server) postfixDeliveryEvidence(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	m, found := s.Store.Get(r.PathValue("id"))
	if !found {
		fail(w, http.StatusNotFound, "Message not found")
		return
	}
	if m.MTAQueueID == "" {
		fail(w, http.StatusConflict, "This scan has no recorded Postfix queue ID")
		return
	}
	if len(m.MTAQueueID) > 32 || !validPostfixEvidenceID(m.MTAQueueID) {
		fail(w, http.StatusConflict, "Recorded Postfix queue ID is invalid")
		return
	}
	path := strings.TrimSpace(os.Getenv("SPAMGATE_POSTFIX_LOG_PATH"))
	if path == "" {
		jsonReply(w, http.StatusOK, map[string]any{"enabled": false, "queue_id": m.MTAQueueID, "events": []deliveryEvidenceEvent{}, "detail": "Configure SPAMGATE_POSTFIX_LOG_PATH with an accessible local Postfix logfile to view evidence."})
		return
	}
	events, truncated, err := readDeliveryEvidence(path, m.MTAQueueID)
	if err != nil {
		s.log.Warn("Postfix evidence read failed", "error", err)
		fail(w, http.StatusServiceUnavailable, "Postfix log unavailable or unsafe; verify configured path and file permissions")
		return
	}
	jsonReply(w, http.StatusOK, map[string]any{"enabled": true, "queue_id": m.MTAQueueID, "events": events, "truncated": truncated, "detail": "Matching Postfix log entries, not an independent mailbox receipt. The current log and one plain-text .1 rotation are inspected with bounded reads; older or compressed logs may be omitted. status=sent indicates acceptance by the next hop, not final inbox placement."})
}

func validPostfixEvidenceID(id string) bool {
	if len(id) == 0 || len(id) > 32 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func readDeliveryEvidence(path, queueID string) ([]deliveryEvidenceEvent, bool, error) {
	if !validPostfixEvidenceID(queueID) {
		return nil, false, errors.New("invalid queue ID")
	}
	// Read one rotated plain-text sibling first, then the active file. Each
	// file has an independent 4 MiB read budget and descriptor safety check.
	// Compressed archives and arbitrary glob expansion are intentionally out.
	var combined []deliveryEvidenceEvent
	truncated := false
	for _, candidate := range []struct { name string; optional bool }{{path + ".1", true}, {path, false}} {
		items, clipped, err := readDeliveryEvidenceFile(candidate.name, queueID)
		if candidate.optional && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, false, err
		}
		truncated = truncated || clipped
		for _, item := range items {
			if len(combined) == evidenceMaxEvents {
				combined = combined[1:]
				truncated = true
			}
			combined = append(combined, item)
		}
	}
	if combined == nil { combined = []deliveryEvidenceEvent{} }
	return combined, truncated, nil
}

func readDeliveryEvidenceFile(path, queueID string) ([]deliveryEvidenceEvent, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, errors.New("log path must be a regular non-symlink file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	// Check that the opened descriptor still points at the inspected object.
	opened, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if !os.SameFile(info, opened) {
		return nil, false, errors.New("log changed during open")
	}
	truncated := false
	if info.Size() > evidenceTailLimit {
		if _, err = f.Seek(info.Size()-evidenceTailLimit, io.SeekStart); err != nil {
			return nil, false, err
		}
		truncated = true
	}
	reader := bufio.NewReaderSize(io.LimitReader(f, evidenceTailLimit), 64*1024)
	if truncated {
		_, _ = reader.ReadString('\n')
	}
	events := make([]deliveryEvidenceEvent, 0, 16)
	for {
		line, e := reader.ReadString('\n')
		if len(line) > 16384 {
			line = line[:16384]
		}
		line = strings.TrimRight(line, "\r\n")
		if match := postfixEvidenceLine.FindStringSubmatch(line); match != nil && match[2] == queueID {
			event := deliveryEvidenceEvent{Line: line}
			// Only a delivery-agent process can provide a status field.
			// Queue manager, cleanup, and SMTP listener log text may contain
			// untrusted values that look like status=sent.
			switch match[1] {
			case "smtp", "lmtp", "local", "virtual", "pipe", "error", "discard":
				if status := postfixStatus.FindStringSubmatch(match[3]); status != nil {
					event.Status = status[1]
				}
			}
			if len(events) == evidenceMaxEvents {
				events = events[1:]
				truncated = true
			}
			events = append(events, event)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, false, e
		}
	}
	return events, truncated, nil
}
