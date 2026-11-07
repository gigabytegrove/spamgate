package transport

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncodedSpoolSizeMatchesRecoveryLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		ok   bool
	}{
		{"empty", 0, false},
		{"one byte", 1, false},
		{"minimum", 2, true},
		{"maximum", maxDurableSpoolRecordBytes, true},
		{"one byte too large", maxDurableSpoolRecordBytes + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateEncodedSpoolSize(tc.size)
			if (err == nil) != tc.ok {
				t.Fatalf("size=%d: error=%v; want accepted=%v", tc.size, err, tc.ok)
			}
		})
	}
}

func TestPutRejectsUnrecoverableRecordBeforeCreatingTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	q := &DeliveryQueue{dir: dir}
	rec := spoolRecord{
		QueuedMessage: QueuedMessage{
			ID: strings.Repeat("a", 32),
			Subject: strings.Repeat("S", maxDurableSpoolRecordBytes),
			State: "queued",
		},
		RawRFC822: []byte("Subject: test\r\n\r\nbody"),
	}
	if err := q.put(rec); err == nil {
		t.Fatal("expected oversized serialized spool to be rejected")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("oversized record left %d files in spool", len(entries))
	}
	if _, err := os.Stat(filepath.Join(dir, rec.ID+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized record unexpectedly published: %v", err)
	}
}
