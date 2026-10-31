//go:build linux

package transport

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gigabytegrove/spamgate/internal/core"
)

func TestDeliveryWorkerLockSerializesHandles(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireDeliveryWorkerLock(context.Background(), dir)
	if err != nil { t.Fatal(err) }
	start := time.Now()
	second, err := acquireDeliveryWorkerLock(context.Background(), dir)
	if second != nil { second(); t.Fatal("second worker acquired active lease") }
	if !errors.Is(err, ErrDeliveryWorkerBusy) { t.Fatalf("unexpected contention result: %v", err) }
	if time.Since(start) > 2*time.Second { t.Fatal("lock contention stalled worker") }
	first()
	first()
	third, err := acquireDeliveryWorkerLock(context.Background(), dir)
	if err != nil { t.Fatalf("worker lease did not recover: %v", err) }
	third()
}

func TestDeliveryWorkerLockHonorsCancellation(t *testing.T) {
	dir := t.TempDir()
	first, err := acquireDeliveryWorkerLock(context.Background(), dir)
	if err != nil { t.Fatal(err) }
	defer first()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	second, err := acquireDeliveryWorkerLock(ctx, dir)
	if second != nil { second(); t.Fatal("canceled worker acquired lease") }
	if !errors.Is(err, context.Canceled) { t.Fatalf("expected context cancellation: %v", err) }
}

func TestDeliveryWorkerLockRefusesUnsafePaths(t *testing.T) {
	for _, tc := range []struct{name string; setup func(*testing.T,string)}{
		{"symlink", func(t *testing.T, dir string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, nil, 0600); err != nil { t.Fatal(err) }
			if err := os.Symlink(target, filepath.Join(dir, deliveryWorkerLockName)); err != nil { t.Fatal(err) }
		}},
		{"hardlink", func(t *testing.T, dir string) {
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, nil, 0600); err != nil { t.Fatal(err) }
			if err := os.Link(target, filepath.Join(dir, deliveryWorkerLockName)); err != nil { t.Fatal(err) }
		}},
		{"world-writable-lock", func(t *testing.T, dir string) {
			path := filepath.Join(dir, deliveryWorkerLockName)
			if err := os.WriteFile(path, nil, 0666); err != nil { t.Fatal(err) }
			if err := os.Chmod(path, 0666); err != nil { t.Fatal(err) }
		}},
		{"world-writable-directory", func(t *testing.T, dir string) {
			if err := os.Chmod(dir, 0777); err != nil { t.Fatal(err) }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			unlock, err := acquireDeliveryWorkerLock(context.Background(), dir)
			if unlock != nil { unlock() }
			if err == nil { t.Fatal("accepted unsafe worker lock filesystem") }
		})
	}
}

func TestIndependentQueueWorkersCannotRelaySameOriginal(t *testing.T) {
	dir := t.TempDir()
	store, err := core.Open(dir)
	if err != nil { t.Fatal(err) }
	entered := make(chan struct{})
	resume := make(chan struct{})
	defer func() { select { case <-resume: default: close(resume) } }()
	sends := 0
	send := func(_ context.Context, _ core.Message, _ []byte) error {
		sends++
		close(entered)
		<-resume
		return nil
	}
	q1, err := NewDeliveryQueue(dir, store, send)
	if err != nil { t.Fatal(err) }
	q2, err := NewDeliveryQueue(dir, store, send)
	if err != nil { t.Fatal(err) }
	m := core.Message{ID:core.ID(), Sender:"sender@example.org", Recipients:[]string{"user@example.org"}}
	if err := q1.Enqueue(m, []byte("Subject: durable\r\n\r\nOriginal")); err != nil { t.Fatal(err) }
	finished := make(chan error, 1)
	go func() { finished <- q1.ProcessDue(context.Background()) }()
	select {
	case <-entered:
	case err := <-finished: t.Fatalf("first worker stopped before relay: %v", err)
	case <-time.After(5*time.Second): t.Fatal("first worker never started relay")
	}
	// The second instance shares a spool but not the first instance's mutex.
	if err := q2.ProcessDue(context.Background()); !errors.Is(err, ErrDeliveryWorkerBusy) {
		t.Fatalf("second instance did not refuse concurrent relay: %v", err)
	}
	snapshot, err := q2.Snapshot()
	if err != nil || snapshot.Total != 1 || snapshot.Delivering != 1 {
		t.Fatalf("in-flight original was not durably retained: %+v %v", snapshot, err)
	}
	close(resume)
	select {
	case err := <-finished: if err != nil { t.Fatal(err) }
	case <-time.After(5*time.Second): t.Fatal("first worker did not finalize")
	}
	if err := q2.ProcessDue(context.Background()); err != nil { t.Fatal(err) }
	if sends != 1 { t.Fatalf("duplicate relay from independent worker: %d", sends) }
	snapshot, err = q2.Snapshot()
	if err != nil || snapshot.Total != 0 { t.Fatalf("delivered original remained in spool: %+v %v", snapshot, err) }
}
