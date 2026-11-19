package main

import (
 "bytes"
 "context"
 "errors"
 "os"
 "path/filepath"
 "testing"

 "github.com/gigabytegrove/spamgate/internal/backupverify"
)

// A cancelled operator request must not create a restore destination.
func TestRestoreCancelledBeforePublication(t *testing.T) {
 base := t.TempDir()
 active := filepath.Join(base, "active")
 backup := filepath.Join(base, "backup")
 if err := os.Mkdir(active, 0700); err != nil { t.Fatal(err) }
 if err := os.Mkdir(backup, 0700); err != nil { t.Fatal(err) }
 if err := os.WriteFile(filepath.Join(backup, "message"), []byte("message"), 0600); err != nil { t.Fatal(err) }
 key := bytes.Repeat([]byte{0x55}, 32)
 keyFile := filepath.Join(base, "key")
 if err := os.WriteFile(keyFile, key, 0600); err != nil { t.Fatal(err) }
 signed, err := backupverify.CreateSignedInventory(backup, key)
 if err != nil { t.Fatal(err) }
 manifest := filepath.Join(base, "manifest")
 if err := writeManifest(manifest, signed); err != nil { t.Fatal(err) }
 target := filepath.Join(base, "restored")
 args := []string{"-operation","restore","-backup",backup,"-manifest",manifest,"-key-file",keyFile,"-active-data",active,"-target",target}
 ctx, cancel := context.WithCancel(context.Background())
 cancel()
 var output bytes.Buffer
 if err := runContext(ctx, args, &output); !errors.Is(err, context.Canceled) { t.Fatalf("wanted context cancellation, got %v",err) }
 if _, err := os.Lstat(target); !os.IsNotExist(err) { t.Fatalf("cancelled restore published target: %v",err) }
 if output.Len() != 0 { t.Fatalf("cancelled restore reported success: %q",output.String()) }
}

func TestRestoreRejectsNilContext(t *testing.T) {
 var output bytes.Buffer
 if err := runContext(nil, nil, &output); err == nil { t.Fatal("nil context accepted") }
}
