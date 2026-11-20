// Command spamgate-backup-verify verifies or cold-restores an authenticated
// quiesced SpamGate backup without touching the running mail server.
package main

import (
 "context"
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "runtime"
 "os/signal"
 "syscall"
 "strings"

 "github.com/gigabytegrove/spamgate/internal/backupverify"
)

func run(args []string, stdout io.Writer) error {
 return runContext(context.Background(), args, stdout)
}

func runContext(ctx context.Context, args []string, stdout io.Writer) error {
 if ctx == nil { return errors.New("operation context required") }
 if err := ctx.Err(); err != nil { return err }
 fs := flag.NewFlagSet("spamgate-backup-verify", flag.ContinueOnError)
 fs.SetOutput(io.Discard)
 operation := fs.String("operation", "verify", "verify or restore")
 root := fs.String("backup", "", "immutable backup directory")
 manifestPath := fs.String("manifest", "", "authenticated manifest JSON")
 keyPath := fs.String("key-file", "", "private raw authentication key file")
 target := fs.String("target", "", "new, nonexistent restore destination")
 active := fs.String("active-data", "/opt/spamgate/data", "active data directory to protect")
 if err := fs.Parse(args); err != nil { return err }
 if len(fs.Args()) != 0 { return errors.New("unexpected positional arguments") }
 if *operation != "verify" && *operation != "restore" { return errors.New("operation must be verify or restore") }
 if *root == "" || *manifestPath == "" || *keyPath == "" { return errors.New("backup, manifest and key-file are required") }
 if *operation == "restore" && *target == "" { return errors.New("restore target required") }
 if *operation == "verify" && *target != "" { return errors.New("target is only valid for restore") }
 if runtime.GOOS != "linux" && *operation == "restore" { return errors.New("cold restore requires Linux") }
 if err := backupverify.CheckBackupBoundary(*active, *root); err != nil { return err }
 if *operation == "restore" {
  if err := checkRestoreSourceBoundary(*root, *target); err != nil { return err }
 }
 if err := checkNativeBackupPaths(*active, *root, *keyPath, *manifestPath); err != nil { return err }
 if *operation == "restore" {
  if err := checkRestoreCredentialBoundary(*target, *manifestPath, *keyPath); err != nil { return err }
 }
 // The operator-supplied active-data path is an additional guard, never a
 // way to disable protection of the immutable native installation path.
 if *operation == "restore" {
  absTarget, err := resolveRestoreTarget(*target)
  if err != nil { return err }
  absActive, err := resolveRestoreTarget(*active)
  if err != nil { return err }
  permanent, err := resolveRestoreTarget("/opt/spamgate/data")
  if err != nil { return err }
  if absTarget == permanent || containsPath(absTarget, permanent) || containsPath(permanent, absTarget) ||
   absTarget == absActive || containsPath(absTarget, absActive) || containsPath(absActive, absTarget) ||
   overlapsPermanentData(absTarget) {
   return errors.New("restore target overlaps active data")
  }
 }
 key, err := readPrivateFile(*keyPath, 4096, backupverify.MinAuthenticationKeyBytes)
 if err != nil { return fmt.Errorf("authentication key: %w", err) }
 defer func(){ for i := range key { key[i] = 0 } }()
 manifestBytes, err := readPrivateFile(*manifestPath, 16<<20, 1)
 if err != nil { return fmt.Errorf("manifest: %w", err) }
 signed, err := backupverify.DecodeSignedManifest(strings.NewReader(string(manifestBytes)))
 if err != nil { return err }
 var report backupverify.Report
 if *operation == "verify" {
  report, err = backupverify.VerifyCompleteContext(ctx, *root, signed, key)
 } else {
  report, err = backupverify.RestoreColdContext(ctx, *root, *target, signed, key)
 }
 if err != nil { return err }
 _, err = fmt.Fprintf(stdout, "%s successful: %d files, %d bytes; no mail services changed\n", *operation, report.Files, report.Bytes)
 return err
}

// resolveRestoreTarget resolves existing parent symlinks even when the final
// destination does not exist. A missing final component must not bypass the
// active-data boundary through a symlinked ancestor.
func resolveRestoreTarget(target string) (string, error) {
 abs, err := filepath.Abs(target)
 if err != nil { return "", err }
 abs = filepath.Clean(abs)
 parent := abs
 var missing []string
 for {
  _, err := os.Lstat(parent)
  if err == nil { break }
  if !errors.Is(err, os.ErrNotExist) { return "", err }
  next := filepath.Dir(parent)
  if next == parent { return "", errors.New("no existing restore ancestor") }
  missing = append(missing, filepath.Base(parent))
  parent = next
 }
 resolved, err := filepath.EvalSymlinks(parent)
 if err != nil { return "", err }
 for i := len(missing)-1; i >= 0; i-- { resolved = filepath.Join(resolved, missing[i]) }
 return filepath.Clean(resolved), nil
}

func overlapsPermanentData(target string) bool {
 const permanentData = "/opt/spamgate/data"
 return target == permanentData || containsPath(target, permanentData) || containsPath(permanentData, target)
}

func containsPath(parent, child string) bool {
 rel, err := filepath.Rel(parent, child)
 return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func main() {
 ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
 defer stop()
 if err := runContext(ctx, os.Args[1:], os.Stdout); err != nil {
  fmt.Fprintln(os.Stderr, "spamgate-backup-verify:", err)
  os.Exit(1)
 }
}
