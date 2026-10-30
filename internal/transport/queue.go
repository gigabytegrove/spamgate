package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

// DeliveryQueue is an intentionally single-node, filesystem-backed, bounded SMTP
// outbox. Returning SMTP 250 requires a synced spool record. Delivery is
// at-least-once: an upstream 250 followed by a local crash can duplicate mail.
const (
	MaxQueueJobs              = 500
	MaxQueueBytes       int64 = 512 << 20
	MaxDeliveryAttempts       = 16
)

type QueuedMessage struct {
	ID          string    `json:"id"`
	Sender      string    `json:"sender"`
	Recipients  []string  `json:"recipients"`
	Subject     string    `json:"subject"`
	Created     time.Time `json:"created"`
	NextAttempt time.Time `json:"next_attempt"`
	Updated     time.Time `json:"updated"`
	Attempts    int       `json:"attempts"`
	State       string    `json:"state"` // queued, delivering, dead, delivered
	LastError   string    `json:"last_error,omitempty"`
	Size        int       `json:"size"`
	DeliveredAt time.Time `json:"delivered_at,omitempty"`
	Raw         []byte    `json:"-"`
}

type spoolRecord struct {
	QueuedMessage
	RawRFC822 []byte `json:"raw"`
	Scan *core.Message `json:"scan,omitempty"` // persisted metadata survives crash before events.jsonl mirror
}

type QueueSummary struct {
	Total      int             `json:"total"`
	Queued     int             `json:"queued"`
	Delivering int             `json:"delivering"`
	Dead       int             `json:"dead"`
	Bytes      int64           `json:"bytes"`
	Jobs       []QueuedMessage `json:"jobs"`
}

type DeliveryQueue struct {
	mu       sync.Mutex
	workerMu sync.Mutex
	dir      string
	store    *core.Store
	send     func(context.Context, core.Message, []byte) error
	now      func() time.Time
}

func NewDeliveryQueue(dataDir string, store *core.Store, deliver func(context.Context, core.Message, []byte) error) (*DeliveryQueue, error) {
	if store == nil || deliver == nil {
		return nil, errors.New("queue requires history store and relay")
	}
	path := filepath.Join(dataDir, "delivery-queue")
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	q := &DeliveryQueue{dir: path, store: store, send: deliver, now: func() time.Time { return time.Now().UTC() }}
	if _, err := q.snapshotLocked(); err != nil {
		return nil, fmt.Errorf("existing spool is not readable: %w", err)
	}
	return q, nil
}
func (q *DeliveryQueue) path(id string) string { return filepath.Join(q.dir, id+".json") }
func (q *DeliveryQueue) syncDirectory() error {
	if runtime.GOOS == "windows" {
		return nil
	} // directory fsync is not supported by Windows file handles
	d, e := os.Open(q.dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (q *DeliveryQueue) put(rec spoolRecord) error {
	b, e := json.Marshal(rec)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(q.dir, ".pending-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(tmp, q.path(rec.ID)); e != nil {
		return e
	}
	return q.syncDirectory()
}
func (q *DeliveryQueue) get(id string) (spoolRecord, error) {
	if len(id) != 32 {
		return spoolRecord{}, os.ErrNotExist
	}
	for _, r := range id {
		if r < '0' || r > '9' {
			if r < 'a' || r > 'f' {
				return spoolRecord{}, os.ErrNotExist
			}
		}
	}
	// Never follow a symlink or load an unbounded, attacker-replaced spool file.
	path := q.path(id)
	meta, e := os.Lstat(path)
	if e != nil { return spoolRecord{}, e }
	if !meta.Mode().IsRegular() || meta.Size() > 20<<20 || meta.Size() < 2 {
		return spoolRecord{}, fmt.Errorf("unsafe or oversized queue job %s", id)
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return spoolRecord{}, e
	}
	var rec spoolRecord
	if e = json.Unmarshal(b, &rec); e != nil {
		return spoolRecord{}, e
	}
	if rec.ID != id || rec.Size <= 0 || rec.Size > 10<<20 || len(rec.RawRFC822) != rec.Size ||
		len(rec.Recipients) == 0 || len(rec.Recipients) > 1000 {
		return spoolRecord{}, fmt.Errorf("invalid queue job %s", id)
	}
	switch rec.State {
	case "queued", "delivering", "delivered", "dead":
	default:
		return spoolRecord{}, fmt.Errorf("invalid queue state %s", id)
	}
	return rec, nil
}
func (q *DeliveryQueue) snapshotLocked() (QueueSummary, error) {
	names, e := os.ReadDir(q.dir)
	if e != nil {
		return QueueSummary{}, e
	}
	var info QueueSummary
	for _, entry := range names {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-5]
		rec, err := q.get(id)
		if err != nil {
			return QueueSummary{}, err
		}
		info.Total++
		info.Bytes += int64(rec.Size)
		switch rec.State {
		case "queued":
			info.Queued++
		case "delivering":
			info.Delivering++
		case "dead":
			info.Dead++
		}
		rec.RawRFC822 = nil
		info.Jobs = append(info.Jobs, rec.QueuedMessage)
	}
	sort.Slice(info.Jobs, func(i, j int) bool { return info.Jobs[i].Created.Before(info.Jobs[j].Created) })
	return info, nil
}
func (q *DeliveryQueue) Snapshot() (QueueSummary, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.snapshotLocked()
}

// Enqueue preserves a complete original and envelope before SMTP acknowledges
// acceptance. A failed spool operation MUST cause SMTP 451, never 250.
func (q *DeliveryQueue) Enqueue(m core.Message, raw []byte) error {
	if m.ID == "" || len(raw) == 0 || len(raw) > 10<<20 {
		return errors.New("invalid queued message")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	summary, e := q.snapshotLocked()
	if e != nil {
		return e
	}
	if summary.Total >= MaxQueueJobs || summary.Bytes+int64(len(raw)) > MaxQueueBytes {
		return errors.New("queue capacity reached")
	}
	now := q.now()
	job := QueuedMessage{ID: m.ID, Sender: m.Sender, Recipients: append([]string(nil), m.Recipients...), Subject: m.Subject, Created: now, Updated: now, NextAttempt: now, Size: len(raw), State: "queued"}
	if _, e = os.Stat(q.path(m.ID)); e == nil {
		return errors.New("queue ID already exists")
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	// Save the complete scan decision with the fsync'd outbox entry. The
	// events.jsonl mirror is best-effort after SMTP 250 and may not exist
	// after an interruption; the queue must be able to reconstruct it.
	saved := m
	saved.HeaderSnapshot = nil
	saved.HeaderTruncated = false
	return q.put(spoolRecord{QueuedMessage: job, RawRFC822: raw, Scan: &saved})
}
func (q *DeliveryQueue) Retry(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	rec, e := q.get(id)
	if e != nil {
		return e
	}
	if rec.State == "delivering" || rec.State == "delivered" {
		return errors.New("message is in flight or already delivered")
	}
	rec.State = "queued"
	rec.NextAttempt = q.now()
	rec.Updated = q.now()
	rec.Attempts = 0
	rec.LastError = ""
	return q.put(rec)
}
func (q *DeliveryQueue) Discard(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	rec, e := q.get(id)
	if e != nil {
		return e
	}
	if rec.State == "delivering" || rec.State == "delivered" {
		return errors.New("cannot discard an in-flight or delivered message")
	}
	if e = os.Remove(q.path(id)); e != nil {
		return e
	}
	return q.syncDirectory()
}
func retryDelay(attempt int) time.Duration {
	delay := 30 * time.Second
	for i := 1; i < attempt && delay < 4*time.Hour; i++ {
		delay *= 2
	}
	if delay > 4*time.Hour {
		return 4 * time.Hour
	}
	return delay
}

// ProcessDue is serial to avoid concurrent sends of one job. A recovered
// 'delivering' entry waits 2 minutes before retry as a crash may have occurred
// after the remote SMTP server accepted the message.
func (q *DeliveryQueue) ProcessDue(ctx context.Context) error {
	q.workerMu.Lock()
	defer q.workerMu.Unlock()
	q.mu.Lock()
	info, e := q.snapshotLocked()
	q.mu.Unlock()
	if e != nil {
		return e
	}
	for _, job := range info.Jobs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if job.State != "queued" && job.State != "delivering" && job.State != "delivered" {
			continue
		}
		if job.State != "delivered" && q.now().Before(job.NextAttempt) {
			continue
		}
		q.mu.Lock()
		rec, err := q.get(job.ID)
		if err != nil {
			q.mu.Unlock()
			return err
		}
		if rec.State == "delivered" {
			q.finalizeLocked(rec)
			q.mu.Unlock()
			continue
		}
		if rec.State == "dead" {
			q.mu.Unlock()
			continue
		}
		rec.State = "delivering"
		rec.Updated = q.now()
		rec.NextAttempt = q.now().Add(2 * time.Minute)
		rec.Attempts++
		if err = q.put(rec); err != nil {
			q.mu.Unlock()
			return err
		}
		q.mu.Unlock()
		msg, ok := q.store.Get(rec.ID)
		if !ok {
			// Restore a missing history entry from the durable outbox before
			// forwarding. Never silently send then delete an untracked mail.
			msg = queueHistoryMessage(rec)
			if err := q.store.Save(msg); err != nil {
				q.mu.Lock()
				// Keep the in-flight spool for a later recovery attempt.
				q.mu.Unlock()
				return fmt.Errorf("cannot reconstruct queued scan history: %w", err)
			}
		}
		sendCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		sendErr := q.send(sendCtx, msg, rec.RawRFC822)
		cancel()
		q.mu.Lock()
		if sendErr != nil {
			rec.LastError = sendErr.Error()
			if len(rec.LastError) > 320 {
				rec.LastError = rec.LastError[:320]
			}
			if rec.Attempts >= MaxDeliveryAttempts {
				rec.State = "dead"
			} else {
				rec.State = "queued"
			}
			rec.NextAttempt = q.now().Add(retryDelay(rec.Attempts))
			rec.Updated = q.now()
			err = q.put(rec)
			if err == nil {
				msg.Delivery = "relay_failed"
				_ = q.store.Save(msg)
			}
			q.mu.Unlock()
			if err != nil {
				return err
			}
			continue
		}
		rec.State = "delivered"
		rec.DeliveredAt = q.now()
		rec.Updated = q.now()
		rec.LastError = ""
		err = q.put(rec)
		if err == nil {
			q.finalizeLocked(rec)
		}
		q.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return nil
}
func queueHistoryMessage(rec spoolRecord) core.Message {
	if rec.Scan != nil && rec.Scan.ID == rec.ID {
		msg := *rec.Scan
		msg.HeaderSnapshot = nil
		msg.HeaderTruncated = false
		msg.Delivery = "queued"
		return msg
	}
	// Older queue formats lacked the full scan; recover the envelope and
	// mark evidence limitations explicitly, never claim an old verdict.
	return core.Message{
		ID: rec.ID, Timestamp: rec.Created,
		Sender: rec.Sender, Recipients: append([]string(nil), rec.Recipients...),
		Subject: rec.Subject, Connector: "smtp", Action: "accept", Delivery: "queued",
		Findings: []core.Finding{{Symbol:"QUEUE_HISTORY_RECOVERED",Source:"recovery/spool",Detail:"Recreated envelope from legacy queue record; original scan evidence unavailable"}},
	}
}
func (q *DeliveryQueue) finalizeLocked(rec spoolRecord) {
	msg, ok := q.store.Get(rec.ID)
	if !ok {
		msg = queueHistoryMessage(rec)
		slog.Warn("reconstructing delivered mail history from durable spool", "id", rec.ID)
	}
	msg.Delivery = "relayed"
	if err := q.store.Save(msg); err != nil {
		slog.Error("delivered mail history persistence failed; retaining durable spool", "id", rec.ID, "error", err)
		return
	}
	if err := os.Remove(q.path(rec.ID)); err != nil {
		return
	}
	_ = q.syncDirectory()
}
func (q *DeliveryQueue) Run(ctx context.Context) {
	timer := time.NewTicker(15 * time.Second)
	defer timer.Stop()
	for {
		if err := q.ProcessDue(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "SpamGate delivery queue: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
