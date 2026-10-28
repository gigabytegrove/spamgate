package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
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
func (s *Server) postfixHoldQueue(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	if os.Getenv("SPAMGATE_POSTFIX_HOLD_INVENTORY") != "true" {
		jsonReply(w, 200, map[string]any{"enabled": false, "messages": []PostfixHeld{}, "detail": "Read-only queue inspection disabled. Set SPAMGATE_POSTFIX_HOLD_INVENTORY=true to allow Postfix queue visibility."})
		return
	}
	messages, err := readPostfixHold(r.Context())
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
