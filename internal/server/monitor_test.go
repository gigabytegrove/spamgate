package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestMonitorDurableAlertLifecycleAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	m := newOperationsMonitor(dir)
	initial := time.Date(2026, 10, 28, 19, 0, 0, 0, time.UTC)
	m.now = func() time.Time { return initial }
	if err := m.record(monitorSample{At: initial, BootID: m.bootID, ScanTotal: 5, ScanErrors: 0, QueueEnabled: true, QueueAvailable: true}); err != nil {
		t.Fatal(err)
	}
	t1 := initial.Add(time.Minute)
	if err := m.record(monitorSample{At: t1, BootID: m.bootID, ScanTotal: 40, ScanErrors: 9, QueueEnabled: true, QueueAvailable: true, QueueDead: 3}); err != nil {
		t.Fatal(err)
	}
	after := newOperationsMonitor(dir)
	state, err := after.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Samples) != 2 || len(state.Alerts) != 2 {
		t.Fatalf("missing persisted evidence: %+v", state)
	}
	for _, a := range state.Alerts {
		if a.State != "open" {
			t.Fatalf("alert not open: %+v", a)
		}
	}
	if err := after.acknowledge(state.Alerts[0].ID, "admin", "reviewed local Postfix logs"); err != nil {
		t.Fatal(err)
	}
	t2 := t1.Add(time.Minute)
	if err := after.record(monitorSample{At: t2, BootID: after.bootID, ScanTotal: 43, ScanErrors: 0, QueueEnabled: true, QueueAvailable: true}); err != nil {
		t.Fatal(err)
	}
	// Require a full same-boot observation interval before declaring scan errors resolved.
	if err := after.record(monitorSample{At: t2.Add(time.Minute), BootID: after.bootID, ScanTotal: 49, ScanErrors: 0, QueueEnabled: true, QueueAvailable: true}); err != nil {
		t.Fatal(err)
	}
	final := newOperationsMonitor(dir)
	saved, err := final.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Samples) != 4 || len(saved.Alerts) != 2 {
		t.Fatalf("evidence not retained: %+v", saved)
	}
	for _, a := range saved.Alerts {
		if a.State != "resolved" || a.ResolvedAt == nil {
			t.Fatalf("alert did not resolve: %+v", a)
		}
	}
	for _, a := range saved.Alerts {
		if a.ID == state.Alerts[0].ID && (a.AcknowledgedBy != "admin" || a.AcknowledgedAt == nil) {
			t.Fatal("acknowledgement was lost")
		}
	}
	info, err := os.Stat(final.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("monitor file permissions: %v", info.Mode())
	}
	if raw, err := os.ReadFile(final.path); err != nil || bytes.Contains(raw, []byte("alice@example.org")) {
		t.Fatal("private content in metrics")
	}
}

func TestMonitorCorruptDataCannotBeOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "operations", "monitor.json")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	m := newOperationsMonitor(dir)
	if _, err := m.snapshot(); err == nil {
		t.Fatal("corrupt monitor data treated as empty")
	}
	if err := m.record(monitorSample{At: time.Now()}); err == nil {
		t.Fatal("corrupt monitor data overwritten")
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != "{broken" {
		t.Fatal("damaged forensic evidence")
	}
}

func TestMonitorBoundedHistoryAndQueueAlerts(t *testing.T) {
	dir := t.TempDir()
	m := newOperationsMonitor(dir)
	m.state.Samples = make([]monitorSample, monitorSamplesLimit)
	for i := range m.state.Samples {
		m.state.Samples[i] = monitorSample{At: time.Unix(int64(i), 0), BootID: m.bootID}
	}
	t1 := time.Now().UTC()
	if err := m.record(monitorSample{At: t1, BootID: m.bootID, QueueEnabled: true, QueueAvailable: false, QueueError: "contains internal error detail"}); err != nil {
		t.Fatal(err)
	}
	s, err := m.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Samples) != monitorSamplesLimit || !s.Samples[0].At.Equal(time.Unix(1, 0)) {
		t.Fatal("monitor retention bound failed")
	}
	if len(s.Alerts) != 1 || s.Alerts[0].Code != "queue_unreadable" {
		t.Fatalf("queue error not surfaced: %+v", s.Alerts)
	}
	// Errors are never reproduced in an alert summary or sent to the browser.
	if strings.Contains(s.Alerts[0].Summary, "contains internal") {
		t.Fatal("untrusted error detail exposed")
	}
}

func TestMonitorAPIAuthorizationAndAcknowledgement(t *testing.T) {
	store, err := core.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	token, hash, err := core.MakeToken()
	if err != nil {
		t.Fatal(err)
	}
	_, otherHash, err := core.MakeToken()
	if err != nil {
		t.Fatal(err)
	}
	if err = store.UpdateConfig(func(c *core.Config) error {
		c.SetupComplete = true
		c.Tokens = []core.Token{{Name: "admin", Hash: hash, Scope: "admin", Created: time.Now()}, {Name: "mailbox", Hash: otherHash, Scope: "mailbox", Created: time.Now()}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s := New(store, nil)
	if err := s.monitorCapture(); err != nil {
		t.Fatal(err)
	}
	router := s.Router()
	request := func(method, path, bearer string, payload []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(payload))
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if w := request("GET", "/api/v1/operations/monitor", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("public monitoring: %d", w.Code)
	}
	w := request("GET", "/api/v1/operations/monitor", token, nil)
	if w.Code != 200 {
		t.Fatalf("admin monitor: %d %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"samples"`)) {
		t.Fatal("no samples")
	}
	if bytes.Contains(w.Body.Bytes(), []byte("@example.org")) {
		t.Fatal("mail metadata leaked")
	}
	if w := request("POST", "/api/v1/operations/monitor/sample", token, nil); w.Code != 200 {
		t.Fatalf("sample: %d %s", w.Code, w.Body.String())
	}
	if err := s.monitor.record(monitorSample{At: time.Now(), BootID: s.monitor.bootID, QueueEnabled: true, QueueAvailable: true, QueueDead: 1}); err != nil {
		t.Fatal(err)
	}
	state, _ := s.monitor.snapshot()
	if len(state.Alerts) == 0 {
		t.Fatal("missing alert")
	}
	id := state.Alerts[0].ID
	if w := request("POST", "/api/v1/operations/monitor/alerts/"+id+"/ack", token, []byte(`{"reason":"short"}`)); w.Code != 409 {
		t.Fatalf("weak reason accepted: %d", w.Code)
	}
	if w := request("POST", "/api/v1/operations/monitor/alerts/"+id+"/ack", token, []byte(`{"reason":"Reviewed mail queue and escalation"}`)); w.Code != 200 {
		t.Fatalf("ack failed: %d %s", w.Code, w.Body.String())
	}
	if w := request("POST", "/api/v1/operations/monitor/alerts/"+id+"/ack", token, []byte(`{"reason":"Repeated acknowledgement should fail"}`)); w.Code != 409 {
		t.Fatalf("duplicate acknowledgement: %d", w.Code)
	}
}

func TestMonitorJsonNeverStoresMessageAddresses(t *testing.T) {
	m := newOperationsMonitor(t.TempDir())
	if err := m.record(monitorSample{At: time.Now(), BootID: m.bootID, QueueEnabled: true, QueueAvailable: true, QueueQueued: 200}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(m.path)
	if err != nil {
		t.Fatal(err)
	}
	var state monitorState
	if err := json.Unmarshal(b, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Alerts) != 1 || state.Alerts[0].Code != "queue_backlog" {
		t.Fatal("threshold not raised")
	}
}
