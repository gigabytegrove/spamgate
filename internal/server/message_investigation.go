package server

// Message investigations combine independently available evidence, never
// treating a scanner verdict, Milter request, or SMTP next-hop acceptance as
// proof of final mailbox delivery.
import (
	"errors"
	"net/http"
	"os"
	"strings"
	"time"
)

type investigationStep struct {
	Name   string    `json:"name"`
	State  string    `json:"state"` // observed, requested, confirmed, failed, unknown, not_applicable
	Detail string    `json:"detail"`
	At     time.Time `json:"at,omitempty"`
}

type investigationResult struct {
	ScanID                  string                  `json:"scan_id"`
	MessageID               string                  `json:"message_id,omitempty"`
	PostfixQueueID          string                  `json:"postfix_queue_id,omitempty"`
	Connector               string                  `json:"connector"`
	Steps                   []investigationStep     `json:"steps"`
	HeaderSnapshotAvailable bool                    `json:"header_snapshot_available"`
	HeaderSnapshotDetail    string                  `json:"header_snapshot_detail"`
	PostfixLogEvents        []deliveryEvidenceEvent `json:"postfix_log_events"`
	PostfixLogTruncated     bool                    `json:"postfix_log_truncated"`
	PostfixHoldPresent      *bool                   `json:"postfix_hold_present,omitempty"`
	PostfixReleaseEnabled   bool                    `json:"postfix_release_enabled"`
	Actions                 []string                `json:"operator_actions"`
	Limitations             []string                `json:"limitations"`
}

func (s *Server) messageInvestigation(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	m, ok := s.Store.Get(r.PathValue("id"))
	if !ok {
		fail(w, 404, "Message not found")
		return
	}
	result := investigationResult{PostfixReleaseEnabled: os.Getenv("SPAMGATE_POSTFIX_HOLD_ACTIONS") == "true" && os.Getenv("SPAMGATE_POSTFIX_HOLD_INVENTORY") == "true", ScanID: m.ID, MessageID: m.MessageID, PostfixQueueID: m.MTAQueueID, Connector: m.Connector,
		Steps: []investigationStep{}, PostfixLogEvents: []deliveryEvidenceEvent{}, Actions: []string{}, Limitations: []string{}}
	add := func(name, state, detail string, at time.Time) {
		result.Steps = append(result.Steps, investigationStep{Name: name, State: state, Detail: detail, At: at})
	}
	add("Intake", "observed", "SpamGate recorded a message through "+m.Connector+". An application scan is not an SMTP transaction receipt.", m.Timestamp)
	add("Scanning", "observed", "Recorded verdict "+m.Action+" with weighted findings; open scoring evidence for per-symbol attribution.", m.Timestamp)
	if _, err := s.Store.Headers(m.ID); err == nil {
		result.HeaderSnapshotAvailable = true
		result.HeaderSnapshotDetail = "Captured inbound headers are available. They precede Postfix's later delivery headers."
	} else if errors.Is(err, os.ErrNotExist) {
		result.HeaderSnapshotDetail = "No retained inbound header snapshot (older scans may predate header capture)."
	} else {
		result.HeaderSnapshotDetail = "Header snapshot could not be inspected: " + err.Error()
	}
	if m.MTAAction != "" {
		add("Milter disposition", "requested", m.MTAAction+"; "+m.MTAActionNote, m.Timestamp)
	} else if m.Connector == "smtp" {
		add("SMTP disposition", "observed", "Recorded SMTP-handling state: "+m.Delivery, m.Timestamp)
	} else {
		add("MTA disposition", "unknown", "No durable MTA action evidence was captured for this scan.", time.Time{})
	}
	if m.MTAQueueID == "" {
		add("Postfix queue", "unknown", "No Postfix queue ID was recorded. Exact log and hold-queue correlation cannot be attempted.", time.Time{})
		result.Actions = append(result.Actions, "Check Postfix Milter macro negotiation and compare Message-ID plus timestamps on the MTA host.")
	} else if !validPostfixEvidenceID(m.MTAQueueID) {
		add("Postfix queue", "failed", "Stored Postfix queue ID has an invalid format; no host commands were run.", time.Time{})
	} else {
		if os.Getenv("SPAMGATE_POSTFIX_HOLD_INVENTORY") == "true" {
			holds, err := s.postfixInventory(r.Context())
			if err != nil {
				add("Postfix hold queue", "unknown", "Cannot read current queue inventory: "+err.Error(), time.Time{})
				result.Actions = append(result.Actions, "Check that postqueue -j is available and readable by the SpamGate service.")
			} else {
				queueIDPresent := 0
				matched := 0
				for _, h := range holds {
					if h.QueueID != m.MTAQueueID {
						continue
					}
					queueIDPresent++
					if correlatesPostfixHold(m, h) {
						matched++
					}
				}
				candidates := s.Store.PostfixHoldCandidates()[m.MTAQueueID]
				present := queueIDPresent == 1 && matched == 1 &&
					len(candidates) == 1 && candidates[0].ID == m.ID
				result.PostfixHoldPresent = &present
				if present {
					add("Postfix hold queue", "confirmed", "A uniquely correlated Postfix HOLD entry matches this scan's complete sender, recipient and arrival evidence. Mailbox delivery is not implied.", time.Now().UTC())
				} else if queueIDPresent > 0 {
					add("Postfix hold queue", "unknown", "The queue ID appears in the hold inventory, but its complete envelope, arrival time or unique scan ownership is not verified. It cannot be attributed to this scan.", time.Now().UTC())
				} else {
					add("Postfix hold queue", "unknown", "The exact queue ID is not in the hold queue. It may have been released, deleted, delivered, or moved; logs are required.", time.Now().UTC())
				}
			}
		} else {
			add("Postfix hold queue", "unknown", "Hold-queue inventory is not enabled; current queue placement has not been checked.", time.Time{})
		}
		path := strings.TrimSpace(os.Getenv("SPAMGATE_POSTFIX_LOG_PATH"))
		if path == "" {
			add("Postfix log", "unknown", "No local Postfix logfile is configured for correlation.", time.Time{})
			result.Actions = append(result.Actions, "Configure read-only SPAMGATE_POSTFIX_LOG_PATH on a host with access to the real mail log.")
		} else {
			events, truncated, err := readDeliveryEvidence(path, m.MTAQueueID)
			if err != nil {
				add("Postfix log", "failed", "Unable to read configured logfile: "+err.Error(), time.Time{})
			} else {
				result.PostfixLogEvents = events
				result.PostfixLogTruncated = truncated
				if len(events) == 0 {
					add("Postfix log", "unknown", "No entries for this exact queue ID in the inspected log tail; rotation or time limits can omit records.", time.Time{})
				}
				if len(events) > 0 {
					add("Postfix log", "observed", "Found "+itoa(len(events))+" entries for this queue ID. Review recipients, times, and each queue transition below.", time.Time{})
					last := events[len(events)-1].Status
					switch last {
					case "sent":
						add("Next-hop transport", "observed", "Postfix recorded status=sent. This verifies next-hop acceptance only, not final INBOX or Junk placement.", time.Time{})
					case "deferred", "bounced", "expired":
						add("Next-hop transport", "failed", "Postfix recorded status="+last+". Inspect the exact SMTP response in the log event.", time.Time{})
					case "hold":
						add("Next-hop transport", "requested", "Postfix log reports a hold. Check the current hold queue to verify whether it remains held.", time.Time{})
					default:
						add("Next-hop transport", "unknown", "A final next-hop acceptance or mailbox outcome was not observed.", time.Time{})
					}
				}
				if truncated {
					result.Limitations = append(result.Limitations, "Log history is truncated to the most recent bounded records; events may be missing.")
				}
			}
		}
	}
	if m.ReviewStatus != "" {
		add("Human review", "observed", m.ReviewStatus+" by "+m.ReviewedBy, m.ReviewedAt)
	}
	if m.OverrideBy != "" {
		add("Operator intervention", "observed", m.OverrideReason+" ("+m.OverrideBy+")", time.Time{})
	}
	result.Limitations = append(result.Limitations, "Queue IDs can be reused; compare timestamps and recipient identities before attributing old logs.")
	result.Limitations = append(result.Limitations, "A SpamGate decision and a Postfix status=sent event do not confirm Dovecot mailbox delivery or Junk-folder placement.")
	result.Actions = append(result.Actions, "Use the raw-header viewer to inspect the message's received authentication inputs; do not treat sender-authored Authentication-Results as trusted.")
	jsonReply(w, 200, result)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [20]byte
	p := len(digits)
	for n > 0 {
		p--
		digits[p] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[p:])
}
