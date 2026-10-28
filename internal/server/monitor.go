package server

// Durable, privacy-limited operations evidence. Samples contain aggregate
// counters and queue sizes only; no recipient, sender, IP, subject or message ID.
// This is a local history, not an assertion of mailbox delivery.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

const monitorSamplesLimit = 2016 // 7 days at 5-minute resolution
const monitorAlertsLimit = 256
const monitorInterval = 5 * time.Minute

type monitorSample struct {
	At              time.Time `json:"at"`
	BootID          string    `json:"boot_id"`
	ScanTotal       uint64    `json:"scan_total"`
	ScanErrors      uint64    `json:"scan_errors"`
	ScannedMilter   uint64    `json:"scanned_milter"`
	ScanSeconds     float64   `json:"scan_seconds"`
	QueueEnabled    bool      `json:"queue_enabled"`
	QueueAvailable  bool      `json:"queue_available"`
	QueueQueued     int       `json:"queue_queued"`
	QueueDelivering int       `json:"queue_delivering"`
	QueueDead       int       `json:"queue_dead"`
	QueueBytes      int64     `json:"queue_bytes"`
	QueueError      string    `json:"queue_error,omitempty"`
}

type monitorAlert struct {
	ID              string     `json:"id"`
	Code            string     `json:"code"`
	Severity        string     `json:"severity"`
	Summary         string     `json:"summary"`
	State           string     `json:"state"` // open or resolved
	FirstSeen       time.Time  `json:"first_seen"`
	LastSeen        time.Time  `json:"last_seen"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy  string     `json:"acknowledged_by,omitempty"`
	Acknowledgement string     `json:"acknowledgement,omitempty"`
}

type monitorState struct {
	Schema  int             `json:"schema"`
	Samples []monitorSample `json:"samples"`
	Alerts  []monitorAlert  `json:"alerts"`
}

type operationsMonitor struct {
	mu        sync.Mutex
	path      string
	bootID    string
	state     monitorState
	loadError error
	now       func() time.Time
}

func newOperationsMonitor(dataDir string) *operationsMonitor {
	m := &operationsMonitor{path: filepath.Join(dataDir, "operations", "monitor.json"), bootID: core.ID(), now: func() time.Time { return time.Now().UTC() }}
	m.state = monitorState{Schema: 1, Samples: []monitorSample{}, Alerts: []monitorAlert{}}
	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return m
	}
	if err == nil {
		if len(data) > 2<<20 {
			err = errors.New("operations history exceeds 2 MiB limit")
		} else {
			var loaded monitorState
			if e := json.Unmarshal(data, &loaded); e != nil {
				err = fmt.Errorf("invalid operations history: %w", e)
			} else if loaded.Schema != 1 || len(loaded.Samples) > monitorSamplesLimit || len(loaded.Alerts) > monitorAlertsLimit {
				err = errors.New("unsupported or oversized operations history")
			} else {
				m.state = loaded
			}
		}
	}
	if err != nil {
		m.loadError = err
	}
	return m
}

// monitorSave writes a same-directory temporary file with a synced, atomic
// rename. A corrupted history is never silently overwritten with empty state.
func (m *operationsMonitor) save(next monitorState) error {
	if m.loadError != nil {
		return fmt.Errorf("monitor history must be recovered before writing: %w", m.loadError)
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0700); err != nil {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(raw) > 2<<20 {
		return errors.New("monitor history size limit reached")
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.path), ".monitor-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(raw)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), m.path); err != nil {
		return err
	}
	// Windows does not support opening directories as regular sync targets.
	if d, e := os.Open(filepath.Dir(m.path)); e == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func monitorThreshold(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 100000 {
		return fallback
	}
	return n
}

func (m *operationsMonitor) record(s monitorSample) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadError != nil {
		return m.loadError
	}
	next := monitorState{Schema: 1, Samples: append(append([]monitorSample(nil), m.state.Samples...), s), Alerts: append([]monitorAlert(nil), m.state.Alerts...)}
	if len(next.Samples) > monitorSamplesLimit {
		next.Samples = next.Samples[len(next.Samples)-monitorSamplesLimit:]
	}
	var previous *monitorSample
	if len(m.state.Samples) > 0 {
		previous = &m.state.Samples[len(m.state.Samples)-1]
	}
	deltas := uint64(0)
	if previous != nil && previous.BootID == s.BootID && s.ScanErrors >= previous.ScanErrors {
		deltas = s.ScanErrors - previous.ScanErrors
	}
	signals := map[string]struct{ severity, summary string }{}
	if s.QueueEnabled && !s.QueueAvailable {
		signals["queue_unreadable"] = struct{ severity, summary string }{"critical", "Durable SMTP queue inventory cannot be read"}
	}
	if s.QueueAvailable && s.QueueDead > 0 {
		signals["queue_dead"] = struct{ severity, summary string }{"critical", fmt.Sprintf("%d dead-letter SMTP jobs require investigation", s.QueueDead)}
	}
	if s.QueueAvailable && s.QueueQueued >= monitorThreshold("SPAMGATE_MONITOR_BACKLOG_THRESHOLD", 100) {
		signals["queue_backlog"] = struct{ severity, summary string }{"warning", fmt.Sprintf("%d accepted SMTP jobs are awaiting delivery", s.QueueQueued)}
	}
	if deltas >= uint64(monitorThreshold("SPAMGATE_MONITOR_SCAN_ERROR_THRESHOLD", 5)) {
		signals["scan_errors"] = struct{ severity, summary string }{"warning", fmt.Sprintf("%d scan failures observed between durable samples", deltas)}
	}
	for i := range next.Alerts {
		a := &next.Alerts[i]
		if a.State != "open" {
			continue
		}
		if active, ok := signals[a.Code]; ok {
			a.LastSeen = s.At
			a.Summary = active.summary
			a.Severity = active.severity
			delete(signals, a.Code)
		} else if a.Code != "scan_errors" || previous != nil && previous.BootID == s.BootID {
			a.State = "resolved"
			t := s.At
			a.ResolvedAt = &t
			a.LastSeen = s.At
		}
	}
	for code, active := range signals {
		next.Alerts = append(next.Alerts, monitorAlert{ID: core.ID(), Code: code, Severity: active.severity, Summary: active.summary, State: "open", FirstSeen: s.At, LastSeen: s.At})
	}
	if len(next.Alerts) > monitorAlertsLimit {
		// Keep all current open alerts. Trim the oldest resolved records first.
		for len(next.Alerts) > monitorAlertsLimit {
			idx := -1
			for i, a := range next.Alerts {
				if a.State == "resolved" {
					idx = i
					break
				}
			}
			if idx < 0 {
				return errors.New("too many unresolved alert records")
			}
			next.Alerts = append(next.Alerts[:idx], next.Alerts[idx+1:]...)
		}
	}
	if err := m.save(next); err != nil {
		return err
	}
	m.state = next
	return nil
}

func (m *operationsMonitor) acknowledge(id, user, reason string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) < 12 || len(reason) > 512 {
		return errors.New("acknowledgement reason must be 12–512 characters")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadError != nil {
		return m.loadError
	}
	next := monitorState{Schema: 1, Samples: append([]monitorSample(nil), m.state.Samples...), Alerts: append([]monitorAlert(nil), m.state.Alerts...)}
	found := false
	for i := range next.Alerts {
		if next.Alerts[i].ID == id {
			if next.Alerts[i].AcknowledgedAt != nil {
				return errors.New("alert already acknowledged")
			}
			t := m.now()
			next.Alerts[i].AcknowledgedAt = &t
			next.Alerts[i].AcknowledgedBy = user
			next.Alerts[i].Acknowledgement = reason
			found = true
			break
		}
	}
	if !found {
		return os.ErrNotExist
	}
	if err := m.save(next); err != nil {
		return err
	}
	m.state = next
	return nil
}

func (m *operationsMonitor) snapshot() (monitorState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.loadError != nil {
		return monitorState{}, m.loadError
	}
	state := monitorState{Schema: m.state.Schema, Samples: append([]monitorSample(nil), m.state.Samples...), Alerts: append([]monitorAlert(nil), m.state.Alerts...)}
	return state, nil
}

func (s *Server) monitorCapture() error {
	t := core.RuntimeScanTelemetry()
	sample := monitorSample{At: s.monitor.now(), BootID: s.monitor.bootID, ScanTotal: t.Total, ScanErrors: t.Errors, ScannedMilter: t.ByConnector["milter"], ScanSeconds: t.DurationSecondsSum, QueueEnabled: s.Queue != nil}
	if s.Queue != nil {
		q, err := s.Queue.Snapshot()
		if err != nil {
			sample.QueueError = "Queue inventory failed; inspect filesystem and logs"
		} else {
			sample.QueueAvailable = true
			sample.QueueQueued = q.Queued
			sample.QueueDelivering = q.Delivering
			sample.QueueDead = q.Dead
			sample.QueueBytes = q.Bytes
		}
	}
	return s.monitor.record(sample)
}
func (s *Server) monitorLoop(ctx context.Context) {
	if err := s.monitorCapture(); err != nil {
		s.log.Error("operations sample failed", "error", err)
	}
	tick := time.NewTicker(monitorInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := s.monitorCapture(); err != nil {
				s.log.Error("operations sample failed", "error", err)
			}
		}
	}
}

func (s *Server) monitorStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, false); !ok {
		return
	}
	state, err := s.monitor.snapshot()
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Operations history unavailable: "+err.Error())
		return
	}
	jsonReply(w, 200, map[string]any{"samples": state.Samples, "alerts": state.Alerts, "sample_interval_seconds": int(monitorInterval.Seconds()), "note": "Only actual scan counters and SpamGate SMTP queue snapshots are recorded. Postfix delivery remains unverified; Milter-only deployments do not enable the SMTP queue."})
}
func (s *Server) monitorSampleNow(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorized(w, r, true, true); !ok {
		return
	}
	if err := s.monitorCapture(); err != nil {
		fail(w, 503, "Unable to persist operations sample: "+err.Error())
		return
	}
	s.monitorStatus(w, r)
}
func (s *Server) monitorAcknowledge(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authorized(w, r, true, true)
	if !ok {
		return
	}
	var request struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &request); err != nil {
		fail(w, 400, "Expected acknowledgement reason")
		return
	}
	err := s.monitor.acknowledge(r.PathValue("id"), id.Name, request.Reason)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fail(w, 404, "Alert not found")
		} else if strings.Contains(err.Error(), "already") || strings.Contains(err.Error(), "reason") {
			fail(w, 409, err.Error())
		} else {
			fail(w, 503, "Unable to persist acknowledgement")
		}
		return
	}
	jsonReply(w, 200, map[string]bool{"acknowledged": true})
}
