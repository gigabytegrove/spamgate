package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHeaderOnlyCaptureAndDurability(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("Return-Path: <sender@fedex.example>\r\nReceived: from mx.test [192.0.2.3]\r\n\tby relay.test\r\nDKIM-Signature: v=1; d=fedex.example;\r\n s=selector; b=fakesignature\r\nSubject: Shipment update\r\n\r\nPRIVATE BODY SECRET\r\n")
	hdr, truncated := CaptureHeaders(raw)
	if truncated || bytes.Contains(hdr, []byte("PRIVATE BODY")) || !bytes.Contains(hdr, []byte("\r\n\tby relay")) {
		t.Fatalf("invalid header snapshot: %q", hdr)
	}
	m := Message{ID: ID(), Timestamp: time.Now(), Recipients: []string{"alice@example.org"}, HeaderSnapshot: hdr, Action: "accept"}
	if err := st.Save(m); err != nil {
		t.Fatal(err)
	}
	snapshot, err := st.Headers(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Raw != string(hdr) || strings.Contains(snapshot.Raw, "PRIVATE BODY") || snapshot.Truncated {
		t.Fatalf("header snapshot mismatch: %+v", snapshot)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(onDisk, []byte("DKIM-Signature")) || bytes.Contains(onDisk, []byte("PRIVATE BODY")) {
		t.Fatal("raw header or body leaked into event history")
	}
	listed := st.List(10, "")
	ser, _ := json.Marshal(listed)
	if bytes.Contains(ser, []byte("DKIM-Signature")) {
		t.Fatal("raw headers leaked in list API")
	}
	file, err := os.Stat(filepath.Join(dir, "headers", m.ID+".hdr"))
	if err != nil {
		t.Fatal(err)
	}
	if file.Mode().Perm() != 0600 {
		t.Fatalf("header permissions: %o", file.Mode().Perm())
	}
	st, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = st.Headers(m.ID)
	if err != nil || snapshot.Raw != string(hdr) {
		t.Fatalf("reload headers: %+v %v", snapshot, err)
	}
	// Reviews write the record again, but must not delete the sidecar.
	revised, _ := st.Get(m.ID)
	revised.ReviewStatus = "correct"
	if err = st.Save(revised); err != nil {
		t.Fatal(err)
	}
	if _, err = st.Headers(m.ID); err != nil {
		t.Fatal("review lost original headers:", err)
	}
	// Retention and history eviction must remove sensitive header sidecars.
	if err := st.UpdateConfig(func(c *Config) error { c.Settings.RetentionDays = 1; return nil }); err != nil {
		t.Fatal(err)
	}
	revised, _ = st.Get(m.ID)
	revised.Timestamp = time.Now().Add(-48 * time.Hour)
	if err = st.Save(revised); err != nil {
		t.Fatal(err)
	}
	if err = st.Compact(); err != nil {
		t.Fatal(err)
	}
	if _, err = st.Headers(m.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired headers still available: %v", err)
	}
	if _, err = os.Stat(filepath.Join(dir, "headers", m.ID+".hdr")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired header file remains: %v", err)
	}
}

func TestHeaderInspectionNeverIncludesBodyAndHasLegacyFallback(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: legitimate@example.org\nSubject: Example\n\nSECRET BODY")
	snap, _ := CaptureHeaders(raw)
	if string(snap) != "From: legitimate@example.org\nSubject: Example" {
		t.Fatalf("LF parsing %q", snap)
	}
	m := Message{ID: ID(), Timestamp: time.Now(), Connector: "milter", Action: "accept"}
	if err = st.Save(m); err != nil {
		t.Fatal(err)
	}
	if _, err = st.Headers(m.ID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy accepted headers invented: %v", err)
	}
	if err = st.Quarantine(m.ID, raw); err != nil {
		t.Fatal(err)
	}
	got, err := st.Headers(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got.Raw, "SECRET BODY") || !strings.Contains(got.Source, "quarantine") {
		t.Fatalf("legacy fallback failed: %+v", got)
	}
	if _, err = st.Headers("../../secret"); err == nil {
		t.Fatal("unsafe ID accepted")
	}
	large := []byte("X-Large: " + strings.Repeat("a", MaxStoredHeaderBytes+20) + "\r\n\r\nSECRET BODY")
	cap, truncated := CaptureHeaders(large)
	if !truncated || len(cap) != MaxStoredHeaderBytes || bytes.Contains(cap, []byte("SECRET BODY")) {
		t.Fatal("unsafe oversized header retention")
	}
	// Scans always extract raw header snapshots, independently of action.
	cfg := st.Config()
	cfg.SetupComplete = true
	message, err := (&Scanner{Store: st}).Scan(context.Background(), Input{Raw: []byte("From: x@example.com\r\nSubject: Hello\r\n\r\nSecret message body"), Connector: "http"})
	if err != nil {
		t.Fatal(err)
	}
	if len(message.HeaderSnapshot) == 0 || bytes.Contains(message.HeaderSnapshot, []byte("Secret message body")) {
		t.Fatalf("scanner failed to capture headers: %+v", message)
	}
}
