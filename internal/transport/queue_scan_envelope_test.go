package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestQueueRejectsSignedScanEnvelopeMismatchBeforeRelay(t *testing.T) {
	cases := []struct {
		name string
		mutate func(*spoolRecord)
	}{
		{"wrong message ID", func(r *spoolRecord) { r.Scan.ID = core.ID() }},
		{"wrong sender", func(r *spoolRecord) { r.Scan.Sender = "other@example.invalid" }},
		{"wrong recipient", func(r *spoolRecord) { r.Scan.Recipients[0] = "other@example.invalid" }},
		{"recipient reordered", func(r *spoolRecord) { r.Scan.Recipients[0], r.Scan.Recipients[1] = r.Scan.Recipients[1], r.Scan.Recipients[0] }},
		{"recipient omitted", func(r *spoolRecord) { r.Scan.Recipients = r.Scan.Recipients[:1] }},
		{"recipient duplicated", func(r *spoolRecord) { r.Scan.Recipients = append(r.Scan.Recipients, r.Scan.Recipients[0]) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, _, _ := newIntegrityQueue(t)
			msg := core.Message{
				ID: core.ID(), Sender: "sender@example.invalid",
				Recipients: []string{"one@example.invalid", "two@example.invalid"},
			}
			if err := q.Enqueue(msg, []byte("Subject: original\r\n\r\nbody")); err != nil {
				t.Fatal(err)
			}
			rec, err := q.get(msg.ID)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&rec)
			// Recalculate both unkeyed checksums: this is a semantically
			// inconsistent but byte-for-byte checksum-valid spool record.
			rec.IntegritySHA256 = spoolDigest(rec)
			if err := q.put(rec); err != nil {
				t.Fatal(err)
			}
			if _, err := q.get(msg.ID); err == nil || !strings.Contains(err.Error(), "scan envelope") {
				t.Fatalf("checksum-valid mismatched scan accepted: %v", err)
			}
			before, err := os.ReadFile(q.path(msg.ID))
			if err != nil {
				t.Fatal(err)
			}
			sends := 0
			q.send = func(context.Context, core.Message, []byte) error {
				sends++
				return nil
			}
			if err := q.ProcessDue(context.Background()); err == nil {
				t.Fatal("worker processed a mismatched scan envelope")
			}
			after, err := os.ReadFile(q.path(msg.ID))
			if err != nil || !bytes.Equal(before, after) || sends != 0 {
				t.Fatalf("unsafe worker side effects: read=%v sends=%d", err, sends)
			}
		})
	}
}

func TestQueueAllowsLegacyAbsentScanEnvelope(t *testing.T) {
	q, _, _ := newIntegrityQueue(t)
	msg := core.Message{
		ID: core.ID(), Sender: "sender@example.invalid",
		Recipients: []string{"one@example.invalid"},
	}
	if err := q.Enqueue(msg, []byte("Subject: legacy\r\n\r\nbody")); err != nil {
		t.Fatal(err)
	}
	rec, err := q.get(msg.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec.Scan = nil
	rec.IntegritySHA256 = spoolDigest(rec)
	if err := q.put(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := q.get(msg.ID); err != nil {
		t.Fatalf("legitimate legacy spool record refused: %v", err)
	}
}

func TestEnqueueRefusesSignedPendingScanEnvelopeMismatch(t *testing.T) {
	q, _, _ := newIntegrityQueue(t)
	_, pending, original := retainAcceptedOriginal(t, q)
	var rec spoolRecord
	if err := json.Unmarshal(original, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Scan == nil {
		t.Fatal("expected durable scan")
	}
	rec.Scan.Recipients = []string{"wrong@example.invalid"}
	rec.IntegritySHA256 = spoolDigest(rec)
	rec.StateSHA256 = spoolStateDigest(rec)
	changed, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pending, changed, 0600); err != nil {
		t.Fatal(err)
	}
	next := core.Message{
		ID: core.ID(), Sender: "sender@example.invalid",
		Recipients: []string{"recipient@example.invalid"},
	}
	if err := q.Enqueue(next, []byte("Subject: unrelated\r\n\r\nbody")); err == nil ||
		!strings.Contains(err.Error(), "scan envelope") {
		t.Fatalf("inconsistent pending scan did not fail closed: %v", err)
	}
	after, err := os.ReadFile(pending)
	if err != nil || !bytes.Equal(changed, after) {
		t.Fatalf("pending forensic evidence changed: %v", err)
	}
	if _, err := os.Stat(q.path(next.ID)); !os.IsNotExist(err) {
		t.Fatalf("new original published despite unsafe pending evidence: %v", err)
	}
}
