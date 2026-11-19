package backupverify

import (
 "bytes"
 "context"
 "errors"
 "io"
 "os"
 "path/filepath"
 "testing"
)

func TestRestoreColdContextCanceledBeforeStaging(t *testing.T) {
 root, _ := fixture(t)
 key := []byte("0123456789abcdef0123456789abcdef")
 signed, err := CreateSignedInventory(root, key)
 if err != nil { t.Fatal(err) }
 parent := t.TempDir()
 target := filepath.Join(parent, "restored")
 ctx, cancel := context.WithCancel(context.Background())
 cancel()
 if _, err := RestoreColdContext(ctx, root, target, signed, key); !errors.Is(err, context.Canceled) {
  t.Fatalf("expected cancellation, got %v", err)
 }
 if _, err := os.Lstat(target); !os.IsNotExist(err) { t.Fatalf("target unexpectedly published: %v", err) }
 entries, err := os.ReadDir(parent)
 if err != nil { t.Fatal(err) }
 if len(entries) != 0 { t.Fatalf("staging artifacts remain: %v", entries) }
}

func TestRestoreColdContextNilRejected(t *testing.T) {
 _, err := RestoreColdContext(nil, "backup", "target", SignedManifest{}, nil)
 if err == nil { t.Fatal("nil context accepted") }
}

type cancelAfterRead struct {
 cancel context.CancelFunc
 reader io.Reader
}
func (r *cancelAfterRead) Read(p []byte) (int, error) {
 n, err := r.reader.Read(p)
 r.cancel()
 return n, err
}

func TestRestoreContextReaderInterruptsCopy(t *testing.T) {
 ctx, cancel := context.WithCancel(context.Background())
 source := &restoreContextReader{
  ctx: ctx,
  reader: &cancelAfterRead{cancel: cancel, reader: bytes.NewReader(bytes.Repeat([]byte("x"), 1<<20))},
 }
 _, err := io.Copy(io.Discard, source)
 if !errors.Is(err, context.Canceled) { t.Fatalf("expected canceled copy, got %v", err) }
}

func TestRestoreColdContextSuccess(t *testing.T) {
 root, _ := fixture(t)
 key := []byte("0123456789abcdef0123456789abcdef")
 signed, err := CreateSignedInventory(root, key)
 if err != nil { t.Fatal(err) }
 target := filepath.Join(t.TempDir(), "restored")
 if _, err := RestoreColdContext(context.Background(), root, target, signed, key); err != nil { t.Fatal(err) }
 if _, err := VerifyComplete(target, signed, key); err != nil { t.Fatal(err) }
}
