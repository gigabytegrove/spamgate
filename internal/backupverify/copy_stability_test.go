package backupverify

import (
 "os"
 "path/filepath"
 "testing"
 "time"
)

func TestStableCopySource(t *testing.T) {
 dir := t.TempDir()
 name := filepath.Join(dir, "source")
 if err := os.WriteFile(name, []byte("original"), 0600); err != nil { t.Fatal(err) }
 f, err := os.Open(name)
 if err != nil { t.Fatal(err) }
 defer f.Close()
 before, err := f.Stat()
 if err != nil { t.Fatal(err) }
 after, err := f.Stat()
 if err != nil { t.Fatal(err) }
 if !stableCopySource(before, after) { t.Fatal("stable source rejected") }
 if stableCopySource(nil, after) || stableCopySource(before, nil) { t.Fatal("missing metadata accepted") }

 replacement := filepath.Join(dir, "replacement")
 if err := os.WriteFile(replacement, []byte("original"), 0600); err != nil { t.Fatal(err) }
 other, err := os.Stat(replacement)
 if err != nil { t.Fatal(err) }
 if stableCopySource(before, other) { t.Fatal("replacement inode accepted") }

 if err := os.WriteFile(name, []byte("longer than original"), 0600); err != nil { t.Fatal(err) }
 changed, err := f.Stat()
 if err != nil { t.Fatal(err) }
 if stableCopySource(before, changed) { t.Fatal("changed size accepted") }
}

func TestStableCopySourceRejectsTimestampChange(t *testing.T) {
 dir := t.TempDir()
 name := filepath.Join(dir, "source")
 if err := os.WriteFile(name, []byte("fixed"), 0600); err != nil { t.Fatal(err) }
 f, err := os.Open(name)
 if err != nil { t.Fatal(err) }
 defer f.Close()
 before, err := f.Stat()
 if err != nil { t.Fatal(err) }
 changedTime := before.ModTime().Add(2 * time.Hour)
 if err := os.Chtimes(name, changedTime, changedTime); err != nil { t.Fatal(err) }
 after, err := f.Stat()
 if err != nil { t.Fatal(err) }
 if stableCopySource(before, after) { t.Fatal("timestamp change accepted") }
}
