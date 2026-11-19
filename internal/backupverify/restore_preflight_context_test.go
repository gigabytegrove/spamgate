package backupverify

import (
 "bytes"
 "context"
 "errors"
 "os"
 "path/filepath"
 "sync/atomic"
 "testing"
)

// cancelAfterChecks is deterministic: cancellation is delivered during the
// initial inventory/verification pass, not before RestoreColdContext begins.
type cancelAfterChecks struct {
 context.Context
 checks atomic.Int32
 limit int32
}
func (c *cancelAfterChecks) Err() error {
 if c.checks.Add(1) >= c.limit { return context.Canceled }
 return nil
}

func TestRestoreColdContextCancelsDuringPreflightVerification(t *testing.T) {
 root := t.TempDir()
 if err := os.WriteFile(filepath.Join(root, "message"), []byte("a mail message"), 0600); err != nil { t.Fatal(err) }
 key := bytes.Repeat([]byte{0x42}, 32)
 signed, err := CreateSignedInventory(root, key)
 if err != nil { t.Fatal(err) }
 target := filepath.Join(t.TempDir(), "restored")
 ctx := &cancelAfterChecks{Context: context.Background(), limit: 5}
 _, err = RestoreColdContext(ctx, root, target, signed, key)
 if !errors.Is(err, context.Canceled) { t.Fatalf("expected cancellation during preflight, got %v", err) }
 if ctx.checks.Load() < ctx.limit { t.Fatal("verification never reached cancellation threshold") }
 if _, err := os.Lstat(target); !os.IsNotExist(err) { t.Fatalf("restore target published after cancellation: %v", err) }
}

func TestRestoreColdContextSuccessfulAuthenticatedCopy(t *testing.T) {
 root := t.TempDir()
 if err := os.WriteFile(filepath.Join(root, "message"), []byte("a mail message"), 0600); err != nil { t.Fatal(err) }
 key := bytes.Repeat([]byte{0x42}, 32)
 signed, err := CreateSignedInventory(root, key)
 if err != nil { t.Fatal(err) }
 target := filepath.Join(t.TempDir(), "restored")
 report, err := RestoreColdContext(context.Background(), root, target, signed, key)
 if err != nil { t.Fatal(err) }
 if report.Files != 1 { t.Fatalf("restored %d files, want 1", report.Files) }
 got, err := os.ReadFile(filepath.Join(target, "message"))
 if err != nil { t.Fatal(err) }
 if string(got) != "a mail message" { t.Fatalf("restored content mismatch: %q", got) }
}
