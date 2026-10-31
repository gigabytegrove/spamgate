package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
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
	IntegritySHA256 string `json:"integrity_sha256,omitempty"` // SHA-256 of immutable ID, envelope and original bytes
	StateSHA256 string `json:"state_sha256,omitempty"` // SHA-256 of mutable delivery state
	Scan *core.Message `json:"scan,omitempty"` // persisted metadata survives crash before events.jsonl mirror
}

type QueueSummary struct {
	Total      int             `json:"total"`
	Queued     int             `json:"queued"`
	Delivering int             `json:"delivering"`
	Dead       int             `json:"dead"`
	Bytes      int64           `json:"bytes"`
	PendingTemps int          `json:"pending_temps"`
	PendingTempBytes int64    `json:"pending_temp_bytes"`
	Jobs       []QueuedMessage `json:"jobs"`
}

type DeliveryQueue struct {
	mu       sync.Mutex
	workerMu sync.Mutex
	dir      string
	store    *core.Store
	send     func(context.Context, core.Message, []byte) error
	now      func() time.Time
	// Fault injection only; production always syncs the actual spool directory.
	syncDirForTest func() error
}

func NewDeliveryQueue(dataDir string, store *core.Store, deliver func(context.Context, core.Message, []byte) error) (*DeliveryQueue, error) {
	if store == nil || deliver == nil {
		return nil, errors.New("queue requires history store and relay")
	}
	path := filepath.Join(dataDir, "delivery-queue")
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("delivery queue must be a real directory without group/world write access")
	}
	q := &DeliveryQueue{dir: path, store: store, send: deliver, now: func() time.Time { return time.Now().UTC() }}
	summary, err := q.snapshotLocked()
	if err != nil {
		return nil, fmt.Errorf("existing spool is not readable: %w", err)
	}
	if summary.PendingTemps > 0 {
		slog.Warn("unpublished SMTP spool temporary files require operator investigation; no originals were deleted", "count", summary.PendingTemps, "bytes", summary.PendingTempBytes)
	}
	return q, nil
}
// A queue ID must never become an arbitrary filesystem path.
func validQueueID(id string) bool {
 if len(id) != 32 { return false }
 for _, r := range id {
  if (r < '0' || r > '9') && (r < 'a' || r > 'f') { return false }
 }
 return true
}

// The digest covers the immutable delivery contract, not mutable retry state.
// Older spool records without a digest remain readable for in-place upgrades.
func spoolDigest(rec spoolRecord) string {
 payload, _ := json.Marshal(struct {
  ID string `json:"id"`
  Sender string `json:"sender"`
  Recipients []string `json:"recipients"`
  Raw []byte `json:"raw"`
  Scan *core.Message `json:"scan,omitempty"`
 }{rec.ID, rec.Sender, rec.Recipients, rec.RawRFC822, rec.Scan})
 sum := sha256.Sum256(payload)
 return hex.EncodeToString(sum[:])
}
// A changed "delivered" bit must never silently bypass a relay attempt.
// This detects accidental corruption; it is not a keyed authentication MAC.
func spoolStateDigest(rec spoolRecord) string {
 payload, _ := json.Marshal(struct {
  ID string `json:"id"`
  Immutable string `json:"immutable"`
  Subject string `json:"subject"`
  Created time.Time `json:"created"`
  Updated time.Time `json:"updated"`
  NextAttempt time.Time `json:"next_attempt"`
  Attempts int `json:"attempts"`
  State string `json:"state"`
  LastError string `json:"last_error"`
  DeliveredAt time.Time `json:"delivered_at"`
  Size int `json:"size"`
 }{rec.ID, rec.IntegritySHA256, rec.Subject, rec.Created, rec.Updated,
   rec.NextAttempt, rec.Attempts, rec.State, rec.LastError, rec.DeliveredAt, rec.Size})
 sum := sha256.Sum256(payload)
 return hex.EncodeToString(sum[:])
}
func (q *DeliveryQueue) path(id string) string { return filepath.Join(q.dir, id+".json") }
func (q *DeliveryQueue) syncDirectory() error {
	if q.syncDirForTest != nil {
		return q.syncDirForTest()
	}
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
	if !validQueueID(rec.ID) { return errors.New("invalid queue record ID") }
	rec.StateSHA256 = spoolStateDigest(rec)
	b, e := json.Marshal(rec)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(q.dir, ".pending-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	// A fully synced unpublished original is forensic evidence if rename
	// fails (for example disk or destination failures). Only remove partial
	// writes; never erase a complete original after persistence failed.
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(tmp)
		}
	}()
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
	complete = true
	// The temporary pathname must itself be durable before rename. File fsync
	// alone does not guarantee that a crash will preserve a newly created
	// directory entry if rename or the following directory sync fails.
	if e = q.syncDirectory(); e != nil {
		return fmt.Errorf("unpublished spool retained at %s but directory durability is unconfirmed: %w", filepath.Base(tmp), e)
	}
 // Preserve synced unpublished evidence rather than overwrite an unsafe destination.
 if existing, inspectErr := os.Lstat(q.path(rec.ID)); inspectErr == nil {
  if inspectErr = validateSpoolMetadata(q.path(rec.ID), existing); inspectErr != nil {
   return fmt.Errorf("durable unpublished spool retained at %s: unsafe existing destination: %w", filepath.Base(tmp), inspectErr)
  }
 } else if !errors.Is(inspectErr, os.ErrNotExist) {
  return fmt.Errorf("durable unpublished spool retained at %s: inspect destination: %w", filepath.Base(tmp), inspectErr)
 }
	if e = os.Rename(tmp, q.path(rec.ID)); e != nil {
		return fmt.Errorf("durable unpublished spool retained at %s: %w", filepath.Base(tmp), e)
	}
	// If directory fsync fails, the published record may exist even though
	// the SMTP caller must return 451. The queue is at-least-once and a
	// client retry can duplicate the message; preserve the published record.
	return q.syncDirectory()
}
// readSpoolFile checks the opened descriptor against the lstat result
// BEFORE reading any message bytes. A replaced path or symlink cannot make
// the queue read a different file between inspection and open. The read is
// bounded even when the file grows after the initial stat.
func readSpoolFile(path string, inspected os.FileInfo) ([]byte, error) {
 const maxRecordSize int64 = 20 << 20
 if !inspected.Mode().IsRegular() || inspected.Size() < 2 || inspected.Size() > maxRecordSize {
  return nil, errors.New("unsafe or oversized queue record")
 }
 f, err := os.Open(path)
 if err != nil { return nil, err }
 defer f.Close()
 opened, err := f.Stat()
 if err != nil { return nil, err }
 if !opened.Mode().IsRegular() || !os.SameFile(inspected, opened) {
  return nil, errors.New("queue record changed between inspection and open")
 }
 if err := validateSpoolMetadata(path, opened); err != nil { return nil, fmt.Errorf("unsafe queue record metadata: %w", err) }
 if opened.Size() < 2 || opened.Size() > maxRecordSize {
  return nil, errors.New("queue record size changed or exceeds limit")
 }
 raw, err := io.ReadAll(io.LimitReader(f, maxRecordSize+1))
 if err != nil { return nil, err }
 after, err := f.Stat()
 if err != nil { return nil, err }
 if int64(len(raw)) != opened.Size() || after.Size() != opened.Size() ||
  !after.ModTime().Equal(opened.ModTime()) || !os.SameFile(opened, after) {
  return nil, errors.New("queue record changed during read")
 }
 return raw, nil
}

func (q *DeliveryQueue) get(id string) (spoolRecord, error) {
 if !validQueueID(id) { return spoolRecord{}, os.ErrNotExist }
 path := q.path(id)
 meta, err := os.Lstat(path)
 if err != nil { return spoolRecord{}, err }
 b, err := readSpoolFile(path, meta)
 if err != nil { return spoolRecord{}, fmt.Errorf("unsafe queue job %s: %w", id, err) }
	var rec spoolRecord
	if err = json.Unmarshal(b, &rec); err != nil {
		return spoolRecord{}, err
	}
	if rec.ID != id || rec.Size <= 0 || rec.Size > 10<<20 || len(rec.RawRFC822) != rec.Size ||
		len(rec.Recipients) == 0 || len(rec.Recipients) > 1000 || rec.Attempts < 0 {
		return spoolRecord{}, fmt.Errorf("invalid queue job %s", id)
	}
	switch rec.State {
	case "queued", "delivering", "delivered", "dead":
	default:
		return spoolRecord{}, fmt.Errorf("invalid queue state %s", id)
	}
	if rec.IntegritySHA256 != "" && rec.IntegritySHA256 != spoolDigest(rec) {
		return spoolRecord{}, fmt.Errorf("queue job %s failed immutable envelope/original integrity check", id)
	}
	if rec.StateSHA256 != "" && rec.StateSHA256 != spoolStateDigest(rec) {
		return spoolRecord{}, fmt.Errorf("queue job %s failed mutable delivery-state integrity check", id)
	}
	return rec, nil
}
func (q *DeliveryQueue) snapshotLocked() (QueueSummary, error) {
	d, e := os.Open(q.dir)
	if e != nil { return QueueSummary{}, e }
	defer d.Close()
	var info QueueSummary
	seen := 0
	for {
		names, readErr := d.ReadDir(128)
		if readErr != nil && !errors.Is(readErr, io.EOF) { return QueueSummary{}, readErr }
		for _, entry := range names {
			seen++
			if seen > 4096 { return QueueSummary{}, errors.New("SMTP spool directory exceeds 4096 entries; inventory refused") }
		// A crash between fsync and rename can leave a .pending-* file.
		// It may contain the only surviving copy of an attempted SMTP intake.
		// Never silently delete it or report a clean queue inventory.
		if strings.HasPrefix(entry.Name(), ".pending-") {
			meta, err := entry.Info()
			if err != nil { return QueueSummary{}, err }
			if !meta.Mode().IsRegular() || meta.Size() < 0 || meta.Size() > 20<<20 {
				return QueueSummary{}, fmt.Errorf("unsafe unpublished spool file: %s", entry.Name())
			}
			if err := validateSpoolMetadata(filepath.Join(q.dir, entry.Name()), meta); err != nil { return QueueSummary{}, fmt.Errorf("unsafe unpublished spool file %s: %w", entry.Name(), err) }
			info.PendingTemps++
			info.PendingTempBytes += meta.Size()
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" { continue }
		if entry.IsDir() { return QueueSummary{}, fmt.Errorf("directory masquerading as queue job: %s", entry.Name()) }
		id := entry.Name()[:len(entry.Name())-5]
		if !validQueueID(id) { return QueueSummary{}, fmt.Errorf("invalid queue filename: %s", entry.Name()) }
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
		if errors.Is(readErr, io.EOF) { break }
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
	if !validQueueID(m.ID) || len(raw) == 0 || len(raw) > 10<<20 || len(m.Recipients) == 0 || len(m.Recipients) > 1000 {
		return errors.New("invalid queued message")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	// The inventory limit and new original must be one transaction across
	// all native intake processes sharing the persistent spool.
	unlockIntake, lockErr := acquireDeliveryIntakeLock(context.Background(), q.dir)
	if lockErr != nil { return fmt.Errorf("cannot serialize SMTP spool intake: %w", lockErr) }
	defer unlockIntake()
	summary, e := q.snapshotLocked()
	if e != nil {
		return e
	}
	// Unpublished originals still reserve forensic spool capacity.
 if summary.Total+summary.PendingTemps >= MaxQueueJobs || summary.Bytes+summary.PendingTempBytes+int64(len(raw)) > MaxQueueBytes {
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
	if saved.Timestamp.IsZero() { saved.Timestamp = now }
	saved.HeaderSnapshot = nil
	saved.HeaderTruncated = false
	rec := spoolRecord{QueuedMessage: job, RawRFC822: append([]byte(nil), raw...), Scan: &saved}
	rec.IntegritySHA256 = spoolDigest(rec)
	return q.put(rec)
}
func (q *DeliveryQueue) Retry(id string) error {
	// Admin mutations must not race a different process that has already
	// selected a job for SMTP delivery. Never wait for that relay to finish.
	unlockWorker, lockErr := acquireDeliveryWorkerLock(context.Background(), q.dir)
	if lockErr != nil { return fmt.Errorf("cannot retry while delivery is active: %w", lockErr) }
	defer unlockWorker()
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
	unlockWorker, lockErr := acquireDeliveryWorkerLock(context.Background(), q.dir)
	if lockErr != nil { return fmt.Errorf("cannot discard while delivery is active: %w", lockErr) }
	defer unlockWorker()
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
// DiscardWithAudit durably journals intent before deleting the only original.
// If journal persistence fails, the queued original must remain untouched.
func (q *DeliveryQueue) DiscardWithAudit(id, actor string) error {
 actor = strings.TrimSpace(actor)
 if actor == "" || len(actor) > 128 || strings.ContainsAny(actor, "\r\n") {
  return errors.New("valid audit actor required")
 }
 unlockWorker, lockErr := acquireDeliveryWorkerLock(context.Background(), q.dir)
 if lockErr != nil { return fmt.Errorf("cannot discard while delivery is active: %w", lockErr) }
 defer unlockWorker()
 q.mu.Lock()
 defer q.mu.Unlock()
 rec, err := q.get(id)
 if err != nil { return err }
 if rec.State == "delivering" || rec.State == "delivered" {
  return errors.New("cannot discard an in-flight or delivered message")
 }
 msg, ok := q.store.Get(id)
 if !ok { msg = queueHistoryMessage(rec) }
 msg.Delivery = "discard_requested"
 msg.OverrideBy = actor
 msg.OverrideReason = "Operator requested permanent deletion of undelivered SMTP original"
 msg.Findings = append(msg.Findings, core.Finding{
  Symbol: "QUEUE_DISCARD_REQUESTED", Source: "manual/" + actor, Detail: msg.OverrideReason,
 })
 if err := q.store.Save(msg); err != nil {
  return fmt.Errorf("refusing unaudited queue discard: %w", err)
 }
 if err := os.Remove(q.path(id)); err != nil { return err }
 if err := q.syncDirectory(); err != nil {
  return fmt.Errorf("queue original removed but directory durability is unconfirmed: %w", err)
 }
 msg.Delivery = "discarded"
 msg.Findings = append(msg.Findings, core.Finding{
  Symbol: "QUEUE_DISCARDED", Source: "manual/" + actor,
  Detail: "Operator permanently deleted undelivered SMTP original",
 })
 if err := q.store.Save(msg); err != nil {
  return fmt.Errorf("queue original removed but final audit failed; discard request remains journaled: %w", err)
 }
 return nil
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
	// The in-memory mutex only protects this queue instance. An independent
	// native worker using the same data root must not start a second relay
	// pass while the first worker is between spool transitions and SMTP 250.
	unlock, lockErr := acquireDeliveryWorkerLock(ctx, q.dir)
	if lockErr != nil {
		return lockErr
	}
	defer unlock()
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
			err = q.finalizeLocked(rec)
			q.mu.Unlock()
			if err != nil { return err }
			continue
		}
		if rec.State == "dead" {
			q.mu.Unlock()
			continue
		}
		// Reconstruct and validate durable history BEFORE consuming a delivery
		// attempt. A journal outage must not transition queued mail into
		// "delivering" or exhaust retries without any SMTP attempt.
		msg, ok := q.store.Get(rec.ID)
		if !ok {
			// Restore a missing history entry from the durable outbox before
			// forwarding. Never silently send then delete an untracked mail.
			msg = queueHistoryMessage(rec)
			if err := q.store.Save(msg); err != nil {
				q.mu.Unlock()
				return fmt.Errorf("cannot reconstruct queued scan history: %w", err)
			}
		}
		// The fsync-backed spool, not the mutable history mirror, owns the
		// SMTP reverse path and recipient set. A damaged or stale history
		// entry must never redirect an accepted message to another mailbox.
		// Restore the original scan evidence and persist the correction before
		// attempting upstream delivery; on journal failure retain the spool.
		if msg.Sender != rec.Sender || !slices.Equal(msg.Recipients, rec.Recipients) {
			slog.Warn("queued history envelope differs from durable spool; restoring authoritative envelope", "id", rec.ID)
			msg = queueHistoryMessage(rec)
			msg.Findings = append(msg.Findings, core.Finding{
				Symbol: "QUEUE_ENVELOPE_RESTORED", Source: "recovery/spool",
				Detail: "History envelope differed from durable spool; original sender and recipients restored before delivery",
			})
			if err := q.store.Save(msg); err != nil {
				q.mu.Unlock()
				return fmt.Errorf("cannot persist authoritative queue envelope for %s: %w", rec.ID, err)
			}
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
		// Never pass an envelope from history to a relay implementation.
		msg.Sender = rec.Sender
		msg.Recipients = append([]string(nil), rec.Recipients...)
		sendCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		sendErr := q.send(sendCtx, msg, rec.RawRFC822)
		cancel()
		q.mu.Lock()
		if sendErr != nil {
			rec.LastError = sendErr.Error()
			if len(rec.LastError) > 320 {
				rec.LastError = rec.LastError[:320]
			}
			permanent := isPermanentRelayFailure(sendErr)
			if permanent || rec.Attempts >= MaxDeliveryAttempts {
				rec.State = "dead"
			} else {
				rec.State = "queued"
			}
			rec.NextAttempt = q.now().Add(retryDelay(rec.Attempts))
			rec.Updated = q.now()
			err = q.put(rec)
			if err == nil {
				if rec.State == "dead" {
					msg.Delivery = "delivery_dead"
					detail := "SMTP delivery attempts exhausted; original retained for operator review"
					if permanent {
						detail = "Upstream SMTP permanently rejected MAIL, RCPT or DATA; original retained for operator review"
						var invalid *invalidRelayOriginalError
						if errors.As(sendErr, &invalid) {
							detail = "SMTP relay refused deterministically invalid original; immutable bytes retained for operator review"
						}
					}
					msg.Findings = append(msg.Findings, core.Finding{
						Symbol: "QUEUE_DELIVERY_DEAD", Source: "smtp/relay", Detail: detail,
					})
				} else {
					msg.Delivery = "relay_failed"
				}
				if historyErr := q.store.Save(msg); historyErr != nil {
					slog.Error("delivery failure history persistence failed; retaining spool", "id", rec.ID, "error", historyErr)
				}
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
		if err == nil { err = q.finalizeLocked(rec) }
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
		if msg.Timestamp.IsZero() { msg.Timestamp = rec.Created }
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
func (q *DeliveryQueue) finalizeLocked(rec spoolRecord) error {
	msg, ok := q.store.Get(rec.ID)
	if !ok {
		msg = queueHistoryMessage(rec)
		slog.Warn("reconstructing delivered mail history from durable spool", "id", rec.ID)
	}
	msg.Delivery = "relayed"
	if err := q.store.Save(msg); err != nil {
		slog.Error("delivered mail history persistence failed; retaining durable spool", "id", rec.ID, "error", err)
		return fmt.Errorf("cannot persist delivered history for %s: %w", rec.ID, err)
	}
	if err := os.Remove(q.path(rec.ID)); err != nil { return fmt.Errorf("cannot remove delivered spool %s: %w", rec.ID, err) }
	if err := q.syncDirectory(); err != nil { return fmt.Errorf("cannot sync delivered spool directory: %w", err) }
	return nil
}
func (q *DeliveryQueue) Run(ctx context.Context) {
	timer := time.NewTicker(15 * time.Second)
	defer timer.Stop()
	for {
		if err := q.ProcessDue(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, ErrDeliveryWorkerBusy) {
			fmt.Fprintf(os.Stderr, "SpamGate delivery queue: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
