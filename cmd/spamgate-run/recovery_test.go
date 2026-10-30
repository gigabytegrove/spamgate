package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A bad worker must not permanently terminate the foreground launcher. A
// repaired worker is picked up automatically without restarting Postfix.
func TestRunnerRecoversAfterBrokenInitialWorker(t *testing.T) {
	if testing.Short() { t.Skip("integration build") }
	dir := t.TempDir()
	broken := buildFixture(t, dir, "broken", "0.6.0-beta.1", true)
	healthy := buildFixture(t, dir, "repaired", "0.6.0-beta.1", false)
	installed := filepath.Join(dir, "spamgate-worker")
	if err := copyAtomic(broken, installed); err != nil { t.Fatal(err) }
	o := options{worker: installed, data: filepath.Join(dir, "data"), listen: port(t)}
	o.args = []string{"-data", o.data, "-listen", o.listen}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervise(ctx, o) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil { t.Errorf("supervisor error: %v", err) }
		case <-time.After(10 * time.Second):
			t.Error("supervisor failed to stop")
		}
	}()
	// Allow the first executable to fail before repairing the same path.
	time.Sleep(600 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("launcher exited on initial worker failure: %v", err)
	default:
	}
	if err := copyAtomic(healthy, installed); err != nil { t.Fatal(err) }
	awaitVersion(t, o.listen, "0.6.0-beta.1")
	resp, err := http.Get("http://" + o.listen + "/healthz")
	if err != nil { t.Fatal(err) }
	resp.Body.Close()
	if resp.StatusCode != 200 { t.Fatalf("recovered worker status %d", resp.StatusCode) }
	if _, err := os.Stat(filepath.Join(o.data, "updates", "runner.lock")); err != nil {
		t.Fatalf("launcher lock missing: %v", err)
	}
}

func TestRecoveryStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := recoverWorker(ctx, options{}, "http://127.0.0.1:1/healthz", "0.6.0-beta.1", 3)
	if err != context.Canceled { t.Fatalf("expected cancellation, got %v", err) }
}
