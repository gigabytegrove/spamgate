// Command spamgate-backup-verify verifies or cold-restores an authenticated
// quiesced SpamGate backup without touching the running mail server.
package main

import (
 "errors"
 "flag"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "runtime"
 "strings"

 "github.com/gigabytegrove/spamgate/internal/backupverify"
)

func run(args []string, stdout io.Writer) error {
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
  absTarget, err := filepath.Abs(*target)
  if err != nil { return err }
  absActive, err := filepath.EvalSymlinks(*active)
  if err != nil { return err }
  absActive, err = filepath.Abs(absActive)
  if err != nil { return err }
  if absTarget == absActive || containsPath(absTarget, absActive) || containsPath(absActive, absTarget) {
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
  report, err = backupverify.VerifyComplete(*root, signed, key)
 } else {
  report, err = backupverify.RestoreCold(*root, *target, signed, key)
 }
 if err != nil { return err }
 _, err = fmt.Fprintf(stdout, "%s successful: %d files, %d bytes; no mail services changed\n", *operation, report.Files, report.Bytes)
 return err
}

func containsPath(parent, child string) bool {
 rel, err := filepath.Rel(parent, child)
 return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func main() {
 if err := run(os.Args[1:], os.Stdout); err != nil {
  fmt.Fprintln(os.Stderr, "spamgate-backup-verify:", err)
  os.Exit(1)
 }
}
