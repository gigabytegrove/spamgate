package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gigabytegrove/spamgate/internal/core"
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
	var output queueLimit
	output.max = 5 << 20
	var stderr queueLimit
	stderr.max = 4096
	cmd.Stdout = &output
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("postqueue -j failed: %w", err)
	}
	return parsePostfixHold(output.Bytes())
}
func parsePostfixHold(payload []byte) ([]PostfixHeld, error) {
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	held := make([]PostfixHeld, 0)
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
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("invalid Postfix queue JSON: %w", err)
		}
		if record.QueueName != "hold" {
			continue
		}
		if len(held) >= 1000 {
			return nil, errors.New("too many held messages for this safe inventory; use postqueue on host")
		}
		if record.QueueID == "" || len(record.QueueID) > 32 || strings.ContainsAny(record.QueueID, " \t\r\n/") {
			return nil, errors.New("invalid Postfix queue identifier")
		}
		item := PostfixHeld{QueueID: record.QueueID, Sender: record.Sender, ArrivalTime: record.ArrivalTime, MessageSize: record.MessageSize}
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
	// Join *exact* queue IDs with prior SpamGate hold requests; never match
	// by sender/subject, which can be spoofed and are not unique.
	scans := s.Store.List(1000, "")
	byQueue := map[string]string{}
	for _, scan := range scans {
		if scan.MTAQueueID != "" && scan.MTAAction == "postfix_hold_requested" {
			byQueue[scan.MTAQueueID] = scan.ID
		}
	}
	for i := range messages {
		messages[i].SpamGateScanID = byQueue[messages[i].QueueID]
	}
	jsonReply(w, 200, map[string]any{"enabled": true, "messages": messages, "detail": "Read-only Postfix hold queue. No automatic release or mailbox placement is implied."})
}

// Postfix operations have their own lock because two administrators must not
// race between checking queue ownership and releasing a held original.
var postfixHoldOperationMutex sync.Mutex

// runPostfixRelease only executes a fixed argument vector; it never invokes a
// shell, interprets operator-controlled command strings or accepts wildcards.
// A non-root native deployment needs a deliberately installed, narrow sudoers
// grant for /usr/sbin/postsuper -H; absent that grant it fails closed.
func runPostfixRelease(ctx context.Context, queueID string) (string, error) {
	if !validPostfixEvidenceID(queueID) {
		return "", errors.New("unsafe Postfix queue identifier")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	name := "/usr/sbin/postsuper"
	args := []string{"-H", queueID}
	if os.Geteuid() != 0 {
		name = "/usr/bin/sudo"
		args = []string{"-n", "/usr/sbin/postsuper", "-H", queueID}
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var output, errOutput queueLimit
	output.max = 8 << 10
	errOutput.max = 8 << 10
	cmd.Stdout = &output
	cmd.Stderr = &errOutput
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("postsuper release failed: %w: %s", err, strings.TrimSpace(errOutput.String()))
	}
	return strings.TrimSpace(output.String() + " " + errOutput.String()), nil
}

// POST /api/v1/messages/{id}/postfix-release is deliberately bound to a
// previously observed SpamGate HOLD request and a matching Postfix queue
// inventory entry. It does not release uncorrelated messages from the host.
func (s *Server) postfixReleaseMessage(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	if os.Getenv("SPAMGATE_POSTFIX_HOLD_ACTIONS") != "true" || os.Getenv("SPAMGATE_POSTFIX_HOLD_INVENTORY") != "true" {
		fail(w, 409, "Postfix hold actions require explicit local administrator opt-in and queue inventory; no mail was changed")
		return
	}
	var req struct {
		QueueID string `json:"queue_id"`
		Confirm string `json:"confirm"`
		Reason  string `json:"reason"`
	}
	if err := decode(r, &req); err != nil {
		fail(w, 400, "Invalid release request")
		return
	}
	if !validPostfixEvidenceID(req.QueueID) || req.Confirm != "release Postfix hold "+req.QueueID || len(strings.TrimSpace(req.Reason)) < 12 || len(req.Reason) > 512 {
		fail(w, 400, "An exact queue ID, explicit confirmation, and 12–512 character reason are required")
		return
	}
	postfixHoldOperationMutex.Lock()
	defer postfixHoldOperationMutex.Unlock()
	m, exists := s.Store.Get(r.PathValue("id"))
	if !exists {
		fail(w, 404, "Message not found")
		return
	}
	if m.MTAQueueID != req.QueueID || m.MTAAction != "postfix_hold_requested" || m.Connector != "milter" {
		fail(w, 409, "This scan does not establish a Postfix Milter HOLD request for the specified queue ID")
		return
	}
	if m.MTAActionState == "release_submitted" || m.MTAActionState == "release_attempted" {
		fail(w, 409, "An earlier release attempt was recorded. Refresh the Postfix queue and logs before trying again")
		return
	}
	held, err := s.postfixInventory(r.Context())
	if err != nil {
		fail(w, 503, "Cannot verify Postfix hold inventory; nothing was released: "+err.Error())
		return
	}
	matched := false
	for _, h := range held {
		if h.QueueID != req.QueueID {
			continue
		}
		if h.ArrivalTime <= 0 || absDuration(m.Timestamp.Sub(time.Unix(h.ArrivalTime, 0))) > 15*time.Minute {
			fail(w, 409, "Queue ID was reused or the queue arrival time cannot be correlated with this scan; nothing was released")
			return
		}
		// Postfix queue identifiers can be reused. Demand a matching envelope
		// sender and ensure every queued recipient belongs to this scan. A
		// message with no reliable sender/recipient evidence fails closed.
		if m.Sender == "" || h.Sender == "" || !strings.EqualFold(strings.Trim(m.Sender, "<>"), strings.Trim(h.Sender, "<>")) {
			fail(w, 409, "Postfix envelope sender does not match the scanned sender; nothing was released")
			return
		}
		if len(h.Recipients) == 0 || len(m.Recipients) == 0 {
			fail(w, 409, "Postfix queue recipients cannot be correlated; nothing was released")
			return
		}
		for _, actual := range h.Recipients {
			recipientMatches := false
			for _, wanted := range m.Recipients {
				if strings.EqualFold(wanted, actual) {
					recipientMatches = true
					break
				}
			}
			if !recipientMatches {
				fail(w, 409, "Held message has a recipient outside the scanned envelope; nothing was released")
				return
			}
		}
		matched = true
		break
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
	output, err := cmd(r.Context(), req.QueueID)
	if err != nil {
		m.Findings = append(m.Findings, core.Finding{Symbol: "POSTFIX_HOLD_RELEASE_COMMAND_FAILED", Source: "postfix/postsuper", Detail: err.Error()})
		_ = s.Store.Save(m)
		s.log.Error("Postfix hold release command failed", "queue_id", req.QueueID, "actor", actor.Name, "error", err)
		fail(w, 503, "Postfix release command failed; review queue state before retry: "+err.Error())
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
	jsonReply(w, 202, map[string]any{"submitted": true, "queue_id": req.QueueID, "postfix_output": output, "detail": "postsuper accepted the release command; queued delivery and mailbox placement remain unverified"})
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
