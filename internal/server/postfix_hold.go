package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gigabytegrove/spamgate/internal/core"
	"github.com/gigabytegrove/spamgate/internal/spooljson"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// PostfixHeld is a read-only view of Postfix's queue, not a SpamGate original.
// It must never be presented as a confirmed SpamGate disposition.
type PostfixHeld struct {
	SpamGateScanID string   `json:"spamgate_scan_id,omitempty"` // Correlated to a previously requested hold, not a delivery receipt
	QueueID        string   `json:"queue_id"`
	Sender         string   `json:"sender"`
	Recipients     []string `json:"recipients"`
	RecipientCount int `json:"recipient_count"`
	RecipientsTruncated bool `json:"recipients_truncated,omitempty"`
	ArrivalTime    int64    `json:"arrival_time"`
	MessageSize    int64    `json:"message_size"`
}
type queueLimit struct {
	bytes.Buffer
	max int
}

func (b *queueLimit) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		return 0, errors.New("Postfix queue inventory exceeds 5 MiB limit")
	}
	return b.Buffer.Write(p)
}
func readPostfixHold(ctx context.Context) ([]PostfixHeld, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/postqueue", "-j")
	// A forked descendant may retain the output pipe after postqueue exits.
	// Never wait indefinitely for inherited descriptors on a mail host.
	cmd.WaitDelay = time.Second
	var output queueLimit
	output.max = 5 << 20
	var stderr queueLimit
	stderr.max = 4096
	cmd.Stdout = &output
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("postqueue -j failed: %w", err)
	}
	return parseValidatedPostfixHold(output.Bytes())
}

// parseValidatedPostfixHold is the common native queue evidence boundary.
// Parsing success alone is insufficient for privileged queue correlation.
func parseValidatedPostfixHold(payload []byte) ([]PostfixHeld, error) {
	items, err := parsePostfixHold(payload)
	if err != nil {
		return nil, err
	}
	// Apply the same authorization-evidence checks to the native reader as
	// to injected providers. Never return partial or unsafe queue evidence.
	if err := validatePostfixReleaseInventory(items); err != nil {
		return nil, err
	}
	return items, nil
}
// A misspelled or unexpected queue name must not be silently treated as a
// non-HOLD entry: that could conceal a held message during authorization.
// These are the queue classes reported by supported Postfix postqueue -j.
func validPostfixQueueName(name string) bool {
    switch name {
    case "maildrop", "incoming", "active", "deferred", "hold":
        return true
    default:
        return false
    }
}

func parsePostfixHold(payload []byte) ([]PostfixHeld, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	held := make([]PostfixHeld, 0)
	seenQueueIDs := make(map[string]struct{})
	for scanner.Scan() {
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var record struct {
			QueueName   string `json:"queue_name"`
			QueueID     string `json:"queue_id"`
			Sender      string `json:"sender"`
			ArrivalTime int64  `json:"arrival_time"`
			MessageSize int64  `json:"message_size"`
			Recipients  []struct {
				Address string `json:"address"`
			} `json:"recipients"`
		}
		// Postfix inventory is authorization evidence for privileged HOLD release.
		// encoding/json silently accepts duplicate keys, including conflicting
		// queue IDs and recipient lists. Refuse ambiguous or aliased JSON before
		// any field is trusted for queue ownership correlation.
		if err := spooljson.Validate(scanner.Bytes()); err != nil {
			return nil, errors.New("ambiguous or malformed Postfix queue JSON")
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("invalid Postfix queue JSON: %w", err)
		}
		// A queue ID must identify exactly one entry across the entire Postfix
		// inventory, not merely within HOLD. An active/deferred entry sharing
		// an ID with a HOLD entry invalidates the evidence for privileged release.
		// Non-HOLD entries need not have the full HOLD envelope fields.
		// Every JSON line is a queue entry, including active and deferred.
		// A missing ID or queue name on a non-HOLD entry cannot be ignored:
		// it might conceal a conflicting queue identity and authorize release
		// of the wrong original. Refuse the entire snapshot instead.
		if !validPostfixQueueName(record.QueueName) || !validPostfixEvidenceID(record.QueueID) || strings.EqualFold(record.QueueID, "ALL") {
			return nil, errors.New("incomplete Postfix queue identity evidence")
		}
		if _, duplicate := seenQueueIDs[record.QueueID]; duplicate {
			return nil, errors.New("duplicate Postfix queue identifier across queues")
		}
		seenQueueIDs[record.QueueID] = struct{}{}
		if record.QueueName != "hold" {
			continue
		}
		// These fields are mandatory authorization evidence. Unmarshal into a
		// value struct alone conflates an absent sender with a real null path
		// and an absent size with an explicitly reported zero-byte message.
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(scanner.Bytes(), &fields); err != nil {
			return nil, errors.New("invalid Postfix HOLD field evidence")
		}
		for _, name := range []string{"queue_id", "sender", "arrival_time", "message_size", "recipients"} {
			value, present := fields[name]
			if !present || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, errors.New("incomplete Postfix HOLD ownership evidence")
			}
		}
		if len(held) >= 1000 {
			return nil, errors.New("too many held messages for this safe inventory; use postqueue on host")
		}
		if record.ArrivalTime <= 0 || record.MessageSize < 0 || len(record.Recipients) == 0 {
			return nil, errors.New("incomplete Postfix HOLD ownership evidence")
		}
		for _, recipient := range record.Recipients {
			if recipient.Address == "" {
				return nil, errors.New("Postfix HOLD recipient address missing")
			}
		}
		if !validPostfixEvidenceID(record.QueueID) {
			return nil, errors.New("invalid Postfix queue identifier")
		}
		item := PostfixHeld{QueueID: record.QueueID, Sender: record.Sender, ArrivalTime: record.ArrivalTime, MessageSize: record.MessageSize, RecipientCount: len(record.Recipients), RecipientsTruncated: len(record.Recipients) > 50}
		for _, r := range record.Recipients {
			if len(item.Recipients) < 50 {
				item.Recipients = append(item.Recipients, r.Address)
			}
		}
		held = append(held, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return held, nil
}
func (s *Server) postfixInventory(ctx context.Context) ([]PostfixHeld, error) {
	if s.PostfixHeldInventory != nil {
		return s.PostfixHeldInventory(ctx)
	}
	return readPostfixHold(ctx)
}

func (s *Server) postfixHoldQueue(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	if os.Getenv("SPAMGATE_POSTFIX_HOLD_INVENTORY") != "true" {
		jsonReply(w, 200, map[string]any{"enabled": false, "messages": []PostfixHeld{}, "detail": "Read-only queue inspection disabled. Set SPAMGATE_POSTFIX_HOLD_INVENTORY=true to allow Postfix queue visibility."})
		return
	}
	messages, err := s.postfixInventory(r.Context())
	if err != nil {
		fail(w, 503, "Postfix hold inventory unavailable. Check that postqueue -j is supported and the SpamGate process has permission; no queue was changed.")
		return
	}
	// A provider can be injected for tests or alternative local inventory sources.
	// Never expose or correlate ambiguous ownership evidence in the read-only API.
	if err := validatePostfixReleaseInventory(messages); err != nil {
		s.log.Error("Postfix hold inventory rejected", "error", err)
		fail(w, 503, "Postfix hold inventory is ambiguous or incomplete; no queue was changed")
		return
	}
	// Do not mutate an inventory provider's backing slice: a cached result
	// could otherwise retain an earlier scan correlation after the queue
	// changes. Always recompute labels from independent evidence.
	messages = append([]PostfixHeld{}, messages...)
	for i := range messages {
		messages[i].SpamGateScanID = ""
	}
	// A queue ID alone is not ownership evidence: Postfix may reuse it.
	// Correlate only one unambiguous scan to one inventory entry, including
	// its arrival time, complete recipient multiset, and reverse path.
	byQueue := s.Store.PostfixHoldCandidates()
	inventoryCount := make(map[string]int)
	for _, held := range messages {
		inventoryCount[held.QueueID]++
	}
	for i := range messages {
		candidates := byQueue[messages[i].QueueID]
		if inventoryCount[messages[i].QueueID] != 1 || len(candidates) != 1 {
			continue
		}
		if correlatesPostfixHold(candidates[0], messages[i]) {
			messages[i].SpamGateScanID = candidates[0].ID
		}
	}
	jsonReply(w, 200, map[string]any{"enabled": true, "messages": messages, "detail": "Read-only Postfix hold queue. No automatic release or mailbox placement is implied."})
}

// Postfix operations have their own lock because two administrators must not
// race between checking queue ownership and releasing a held original.
var postfixHoldOperationMutex sync.Mutex

// postfixReleaseCommand never grants the worker broad sudo access to
// postsuper. A non-root native worker must invoke the explicitly installed,
// root-owned narrow helper. No fallback to sudo postsuper is permitted.
func postfixReleaseCommand(euid int, queueID string) (string, []string, error) {
	if !validPostfixEvidenceID(queueID) || strings.EqualFold(queueID, "ALL") {
		return "", nil, errors.New("unsafe Postfix queue identifier")
	}
	if euid == 0 {
		return "/usr/sbin/postsuper", []string{"-H", queueID}, nil
	}
	return "/usr/bin/sudo", []string{"-n", "--", "/usr/local/libexec/spamgate/postfix-hold-release", queueID}, nil
}

// runPostfixRelease only executes fixed absolute paths and arguments. The
// privileged helper independently validates the queue ID before invoking
// Postfix. Command success does not prove downstream delivery.
func runPostfixRelease(ctx context.Context, queueID string) (string, error) {
	name, args, err := postfixReleaseCommand(os.Geteuid(), queueID)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	// A helper descendant must not keep inherited pipes open indefinitely.
	cmd.WaitDelay = time.Second
	var output, errOutput queueLimit
	output.max = 8 << 10
	errOutput.max = 8 << 10
	cmd.Stdout = &output
	cmd.Stderr = &errOutput
	if err := classifyPostfixReleaseCompletion(ctx, cmd.Run()); err != nil {
		// A launched Postfix command can change queue state even when its
		// process exits unsuccessfully. Exit 70 is the narrow helper's explicit
		// indeterminate contract; all other post-launch failures must also
		// fail closed. Never forward child output or private host paths.
		return "", err
	}
	// Successful privileged output is not an API contract. In particular,
	// stderr can include envelope addresses and local filesystem paths.
	return "Postfix HOLD release command completed", nil
}

// POST /api/v1/messages/{id}/postfix-release is deliberately bound to a
// previously observed SpamGate HOLD request and a matching Postfix queue
// inventory entry. It does not release uncorrelated messages from the host.
func (s *Server) postfixReleaseMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	if os.Getenv("SPAMGATE_POSTFIX_HOLD_ACTIONS") != "true" || os.Getenv("SPAMGATE_POSTFIX_HOLD_INVENTORY") != "true" {
		fail(w, 409, "Postfix hold actions require explicit local administrator opt-in and queue inventory; no mail was changed")
		return
	}
	req, err := decodePostfixReleaseRequest(r)
	if err != nil {
		fail(w, 400, "Invalid release request")
		return
	}
	if !validPostfixEvidenceID(req.QueueID) || req.Confirm != "release Postfix hold "+req.QueueID || !validPostfixReleaseReason(req.Reason) {
		fail(w, 400, "An exact queue ID, explicit confirmation, and 12–512 character reason are required")
		return
	}
	postfixHoldOperationMutex.Lock()
	defer postfixHoldOperationMutex.Unlock()
	// The in-process mutex does not protect a second SpamGate worker or
	// supervisor instance sharing this data directory. Keep a Linux advisory
	// lock across inventory correlation, the durable intent audit, and
	// postsuper execution. An unavailable lock fails closed.
	unlock, lockErr := acquirePostfixHoldReleaseLock(r.Context(), s.Store.DataDir())
	if lockErr != nil {
		s.log.Error("Postfix hold release lock unavailable", "queue_id", req.QueueID, "error", lockErr)
		fail(w, http.StatusServiceUnavailable, "Cannot obtain exclusive Postfix hold release lock; no queue was changed")
		return
	}
	defer unlock()
	m, exists := s.Store.Get(r.PathValue("id"))
	if !exists {
		fail(w, 404, "Message not found")
		return
	}
	if m.MTAQueueID != req.QueueID || m.MTAAction != "postfix_hold_requested" || m.Connector != "milter" {
		fail(w, 409, "This scan does not establish a Postfix Milter HOLD request for the specified queue ID")
		return
	}
	// A valid scan ID is insufficient if the same Postfix queue ID also
	// belongs to another retained HOLD scan. Refuse ambiguous ownership.
	candidates := s.Store.PostfixHoldCandidates()[req.QueueID]
	if len(candidates) != 1 || candidates[0].ID != m.ID {
		fail(w, 409, "Postfix queue ID has ambiguous or missing retained scan ownership; nothing was released")
		return
	}
	if m.MTAActionState == "release_submitted" || m.MTAActionState == "release_attempted" {
		fail(w, 409, "An earlier release attempt was recorded. Refresh the Postfix queue and logs before trying again")
		return
	}
	held, err := s.postfixInventory(r.Context())
	if err != nil {
		s.log.Error("Postfix hold inventory verification failed before release", "queue_id", req.QueueID, "error", err)
		fail(w, 503, "Cannot verify Postfix hold inventory; nothing was released")
		return
	}
	if err := validatePostfixReleaseInventory(held); err != nil {
		s.log.Error("Postfix release inventory rejected", "error", err)
		fail(w, 409, "Postfix queue inventory is ambiguous or incomplete; nothing was released")
		return
	}
	matched := false
	for _, held := range held {
		if held.QueueID != req.QueueID {
			continue
		}
		if matched {
			fail(w, 409, "Multiple Postfix queue records share this ID; release refused")
			return
		}
		if !correlatesPostfixHold(m, held) {
			fail(w, 409, "Held message does not match the scan's complete envelope and arrival evidence; nothing was released")
			return
		}
		matched = true
	}
	if !matched {
		fail(w, 409, "The exact message is not currently present in Postfix's hold queue; nothing was released")
		return
	}
	// Record a durable audit BEFORE invoking an irreversible MTA operation.
	m.MTAActionState = "release_attempted"
	m.OverrideBy = actor.Name
	m.OverrideReason = "Postfix hold release requested: " + strings.TrimSpace(req.Reason)
	m.Findings = append(m.Findings, core.Finding{Symbol: "POSTFIX_HOLD_RELEASE_ATTEMPT", Source: "manual/" + actor.Name, Detail: m.OverrideReason})
	if err := s.Store.Save(m); err != nil {
		fail(w, 503, "Cannot persist release audit; nothing was released")
		return
	}
	cmd := s.PostfixReleaseHeld
	if cmd == nil {
		cmd = runPostfixRelease
	}
	_, err = cmd(r.Context(), req.QueueID)
	// Apply the same completion contract to injected release executors as to
	// the native subprocess. A canceled HTTP request must never turn a
	// completed queue mutation into a confirmed API success.
	err = classifyPostfixReleaseCompletion(r.Context(), err)
	if err != nil {
		// The intent was persisted before execution. Retain it as a durable
		// retry barrier, even when the helper returns a refusal or the worker
		// cannot determine whether Postfix acted.
		symbol := "POSTFIX_HOLD_RELEASE_COMMAND_FAILED"
		if errors.Is(err, errPostfixReleaseOutcomeUnknown) {
			symbol = "POSTFIX_HOLD_RELEASE_OUTCOME_UNKNOWN"
		}
		m.Findings = append(m.Findings, core.Finding{Symbol: symbol, Source: "postfix/postsuper", Detail: postfixReleaseFailureAuditDetail()})
		if saveErr := s.Store.Save(m); saveErr != nil {
			s.log.Error("Postfix release outcome audit persistence failed", "queue_id", req.QueueID, "error", saveErr)
		}
		s.log.Error("Postfix hold release requires reconciliation", "queue_id", req.QueueID, "actor", actor.Name, "error_class", symbol)
		fail(w, 503, "Postfix release outcome requires queue reconciliation; automatic retry is prohibited")
		return
	}
	m.MTAActionState = "release_submitted"
	m.Delivery = "postfix_release_submitted"
	m.Findings = append(m.Findings, core.Finding{Symbol: "POSTFIX_HOLD_RELEASE_SUBMITTED", Source: "postfix/postsuper", Detail: "postsuper -H returned success; this does not verify downstream delivery"})
	if err := s.Store.Save(m); err != nil {
		s.log.Error("Postfix command succeeded but final audit update failed", "queue_id", req.QueueID, "error", err)
		jsonReply(w, 202, map[string]any{"submitted": true, "audit_incomplete": true, "queue_id": req.QueueID, "detail": "Postfix release command returned success but the final audit write failed. Do not retry without inspecting the queue."})
		return
	}
	s.log.Info("Postfix hold release submitted", "queue_id", req.QueueID, "actor", actor.Name)
	// Raw helper output is not an API contract and may disclose host details.
	jsonReply(w, 202, map[string]any{"submitted": true, "queue_id": req.QueueID, "detail": "postsuper accepted the release command; queued delivery and mailbox placement remain unverified"})
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// postfixReleaseFailureAuditDetail is persisted in the message record and may
// be displayed by the browser API. Never persist privileged helper stderr,
// executable paths, host configuration, or internal error text here.
func postfixReleaseFailureAuditDetail() string {
	return "Postfix hold release command failed; inspect privileged server logs and live queue state before manual intervention"
}
