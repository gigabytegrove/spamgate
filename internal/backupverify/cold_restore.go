package backupverify

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strings"
)

// RestoreCold creates a new native data tree from an authenticated backup.
// The target MUST NOT exist. It never replaces live data, invokes Postfix,
// or changes systemd services. Call only while the backup is immutable.
func RestoreCold(backupRoot, target string, signed SignedManifest, key []byte) (Report, error) {
 return RestoreColdContext(context.Background(), backupRoot, target, signed, key)
}

// RestoreColdContext permits an operator to cancel a long-running cold restore
// without publishing a partial tree. Cancellation is checked during copying.
func RestoreColdContext(ctx context.Context, backupRoot, target string, signed SignedManifest, key []byte) (Report, error) {
 if ctx == nil { return Report{}, errors.New("restore context required") }
 if err := ctx.Err(); err != nil { return Report{}, err }
 var report Report
 if err := AuthenticateManifest(signed, key); err != nil { return report, err }
 if target == "" || backupRoot == "" { return report, errors.New("backup and target required") }
 if _, err := VerifyComplete(backupRoot, signed, key); err != nil { return report, fmt.Errorf("backup verification: %w", err) }
 absTarget, err := filepath.Abs(target)
 if err != nil { return report, err }
 if absTarget == string(filepath.Separator) || filepath.Base(absTarget) == "." { return report, errors.New("unsafe restore target") }
 parent := filepath.Dir(absTarget)
 resolvedParent, err := filepath.EvalSymlinks(parent)
 if err != nil { return report, err }
 if resolvedParent != parent { return report, errors.New("restore parent contains symlink") }
 st, err := os.Lstat(parent)
 if err != nil { return report, err }
 if !st.IsDir() { return report, errors.New("restore parent is not a directory") }
 if _, err := os.Lstat(absTarget); err == nil { return report, errors.New("restore target already exists") } else if !os.IsNotExist(err) { return report, err }
 resolvedBackup, err := filepath.EvalSymlinks(backupRoot)
 if err != nil { return report, err }
 resolvedBackup, err = filepath.Abs(resolvedBackup)
 if err != nil { return report, err }
 if absTarget == resolvedBackup || inside(absTarget, resolvedBackup) || inside(resolvedBackup, absTarget) {
  return report, errors.New("restore target overlaps backup")
 }
 stage, err := os.MkdirTemp(parent, ".spamgate-restore-")
 if err != nil { return report, err }
 defer os.RemoveAll(stage)
 for _, e := range signed.Manifest.Files {
  if err := ctx.Err(); err != nil { return Report{}, err }
  source, err := openVerifiedPath(backupRoot, e.Path)
  if err != nil { return Report{}, err }
  dest := filepath.Join(stage, filepath.FromSlash(e.Path))
  if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil { source.Close(); return Report{}, err }
  out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
  if err != nil { source.Close(); return Report{}, err }
  before, statErr := source.Stat()
  if statErr != nil { _ = out.Close(); _ = source.Close(); return Report{}, statErr }
  if !before.Mode().IsRegular() || before.Size() != e.Size {
   _ = out.Close(); _ = source.Close()
   return Report{}, fmt.Errorf("restore source size or type changed for %q", e.Path)
  }
  h := sha256.New()
  n, copyErr := io.Copy(io.MultiWriter(out,h), &restoreContextReader{ctx:ctx, reader:io.LimitReader(source,e.Size+1)})
  after, afterErr := source.Stat()
  syncErr := out.Sync()
  closeErr := out.Close()
  sourceErr := source.Close()
  if err := ctx.Err(); err != nil { return Report{}, err }
  if copyErr != nil || afterErr != nil || syncErr != nil || closeErr != nil || sourceErr != nil || n != e.Size || hex.EncodeToString(h.Sum(nil)) != e.SHA256 || !stableCopySource(before, after) {
   return Report{}, fmt.Errorf("restore copy failed integrity check for %q", e.Path)
  }
  report.Files++
  report.Bytes += n
 }
 if err := ctx.Err(); err != nil { return Report{}, err }
 // Detect unexpected files or concurrent backup mutation before publishing.
 if _, err := VerifyComplete(backupRoot, signed, key); err != nil { return Report{}, fmt.Errorf("backup changed during restore: %w", err) }
 // Flush created directories before publishing the completed tree.
 dirs := map[string]bool{stage:true}
 for _, e := range signed.Manifest.Files {
  for dir := filepath.Dir(filepath.Join(stage,filepath.FromSlash(e.Path))); strings.HasPrefix(dir,stage+string(filepath.Separator)); dir=filepath.Dir(dir) { dirs[dir]=true }
 }
 for dir := range dirs {
  f, err := os.Open(dir)
  if err != nil { return Report{}, err }
  err=f.Sync()
  closeErr:=f.Close()
  if err != nil { return Report{}, err }
  if closeErr != nil { return Report{}, closeErr }
 }
 // Re-read the staged tree using the hardened descriptor-relative verifier.
 // This detects corruption and unexpected mutation after each file was copied.
 // Staging must remain private and quiesced until publication.
 if _, err := VerifyComplete(stage, signed, key); err != nil { return Report{}, fmt.Errorf("staged restore verification: %w", err) }
 // A preflight check provides a useful error, but only the atomic Linux
 // no-replace publish prevents replacement by a concurrent creator.
 if _, err := os.Lstat(absTarget); err == nil { return Report{}, errors.New("restore target appeared during staging") } else if !os.IsNotExist(err) { return Report{}, err }
 if err := ctx.Err(); err != nil { return Report{}, err }
 if err := publishRestore(stage,absTarget); err != nil { return Report{}, err }
 if f,err:=os.Open(parent);err==nil { _=f.Sync(); _=f.Close() }
 return report,nil
}
