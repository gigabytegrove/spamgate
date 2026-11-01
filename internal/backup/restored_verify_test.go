package backup

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func restoredFixture(t *testing.T) (string, string) {
 t.Helper()
 root := t.TempDir()
 source := filepath.Join(root, "source")
 if err := os.MkdirAll(filepath.Join(source, "delivery-queue"), 0700); err != nil { t.Fatal(err) }
 for name, data := range map[string]string{
  "config.json": "{\"setup_complete\":true}",
  "delivery-queue/queued.eml": "Subject: queued\r\n\r\nbody\r\n",
  "events.jsonl": "{\"id\":\"1\"}\n",
 } {
  if err := os.WriteFile(filepath.Join(source, name), []byte(data), 0600); err != nil { t.Fatal(err) }
 }
 archive := filepath.Join(root, "snapshot.zip")
 if err := Create(source, archive); err != nil { t.Fatal(err) }
 dest := filepath.Join(root, "restored")
 if err := Restore(archive, dest); err != nil { t.Fatal(err) }
 return archive, dest
}

func TestVerifyRestoredRoundTripAndEphemeralLocks(t *testing.T) {
 archive, dest := restoredFixture(t)
 manifest, err := VerifyRestored(archive, dest)
 if _, lockErr := os.Lstat(filepath.Join(dest, ".worker.lock")); !os.IsNotExist(lockErr) { t.Fatalf("verification created worker lock: %v", lockErr) }
 if err != nil || len(manifest.Entries) != 3 { t.Fatalf("valid cold restore rejected: %+v %v", manifest, err) }
 for _, name := range []string{".worker.lock", ".events-journal.lock", "delivery-queue/.delivery-worker.lock"} {
  if err := os.WriteFile(filepath.Join(dest, name), nil, 0600); err != nil { t.Fatal(err) }
 }
 if _, err := VerifyRestored(archive, dest); err != nil { t.Fatalf("ephemeral runtime lock refused: %v", err) }
}

func TestVerifyRestoredDetectsChangedMissingAndUnexpectedFiles(t *testing.T) {
 for _, tc := range []struct {
  name string
  change func(t *testing.T, dest string)
  want string
 }{
  {"tampered", func(t *testing.T, dest string) {
   if err := os.WriteFile(filepath.Join(dest, "config.json"), []byte("{\"setup_complete\":null}"), 0600); err != nil { t.Fatal(err) }
  }, "SHA-256"},
  {"missing", func(t *testing.T, dest string) {
   if err := os.Remove(filepath.Join(dest, "events.jsonl")); err != nil { t.Fatal(err) }
  }, "missing"},
  {"extra-file", func(t *testing.T, dest string) {
   if err := os.WriteFile(filepath.Join(dest, "unexpected.txt"), []byte("extra"), 0600); err != nil { t.Fatal(err) }
  }, "unexpected restored file"},
  {"extra-dir", func(t *testing.T, dest string) {
   if err := os.Mkdir(filepath.Join(dest, "untracked"), 0700); err != nil { t.Fatal(err) }
  }, "unexpected restored directory"},
  {"symlink", func(t *testing.T, dest string) {
   if err := os.Remove(filepath.Join(dest, "events.jsonl")); err != nil { t.Fatal(err) }
   if err := os.Symlink("config.json", filepath.Join(dest, "events.jsonl")); err != nil { t.Skip(err) }
  }, "symlink"},
  {"runtime-lock-symlink", func(t *testing.T, dest string) {
   if err := os.Symlink("config.json", filepath.Join(dest, ".events-journal.lock")); err != nil { t.Skip(err) }
  }, "symlink"},
 } {
  t.Run(tc.name, func(t *testing.T) {
   archive, dest := restoredFixture(t)
   tc.change(t, dest)
   _, err := VerifyRestored(archive, dest)
   if err == nil || !strings.Contains(err.Error(), tc.want) { t.Fatalf("expected %q failure, got %v", tc.want, err) }
  })
 }
}

func TestVerifyRestoredRejectsDestinationSymlinkAndInvalidArchive(t *testing.T) {
 archive, dest := restoredFixture(t)
 alias := filepath.Join(filepath.Dir(dest), "alias")
 if err := os.Symlink(dest, alias); err != nil { t.Skip(err) }
 if _, err := VerifyRestored(archive, alias); err == nil || !strings.Contains(err.Error(), "real directory") {
  t.Fatalf("accepted symlink destination: %v", err)
 }
 if _, err := VerifyRestored(filepath.Join(filepath.Dir(dest), "missing.zip"), dest); err == nil {
  t.Fatal("accepted missing backup archive")
 }
}

func TestVerifyRestoredRejectsRuntimeOnlyManifest(t *testing.T) {
 root := t.TempDir()
 if err := os.WriteFile(filepath.Join(root, ".worker.lock"), nil, 0600); err != nil { t.Fatal(err) }
 manifest := Manifest{Entries: []Entry{{Path: ".worker.lock", Bytes: 0}}}
 if err := verifyRestoredTree(manifest, root); err == nil || !strings.Contains(err.Error(), "no persistent files") {
  t.Fatalf("accepted runtime-only manifest: %v", err)
 }
}
