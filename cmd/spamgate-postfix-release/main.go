//go:build linux

package main

import (
 "context"
 "errors"
 "fmt"
 "io"
 "os"
 "os/exec"
 "strings"
 "unicode/utf8"
 "unicode"
 "sync"
 "syscall"
 "time"
)

const postsuperPath = "/usr/sbin/postsuper"
const commandTimeout = 8 * time.Second
const maxOutput = 8192

func validQueueID(id string) bool {
 if len(id) == 0 || len(id) > 32 || strings.EqualFold(id, "ALL") { return false }
 for i := 0; i < len(id); i++ {
  c := id[i]
  if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') { return false }
 }
 return true
}

var errOutputLimit = errors.New("Postfix command output exceeds safe limit")

// outputBudget is shared by stdout and stderr; each write reserves bytes atomically.
type outputBudget struct {
 mu sync.Mutex
 remaining int
 exceeded bool
}

type boundedOutput struct {
 data []byte
 limit int
 budget *outputBudget
}

func (b *boundedOutput) Write(p []byte) (int, error) {
 if b.budget != nil {
  b.budget.mu.Lock()
  defer b.budget.mu.Unlock()
 }
 remaining := b.limit - len(b.data)
 if b.budget != nil { remaining = b.budget.remaining }
 if remaining < 0 || len(p) > remaining {
  if b.budget != nil { b.budget.exceeded = true }
  return 0, errOutputLimit
 }
 b.data = append(b.data, p...)
 if b.budget != nil { b.budget.remaining -= len(p) }
 return len(p), nil
}

func runWith(ctx context.Context, args []string, uid int, invoke func(context.Context, string, []string) error) error {
 if uid != 0 { return errors.New("Postfix release helper must run as root through an explicit host privilege grant") }
 if len(args) != 1 || !validQueueID(args[0]) { return errors.New("exactly one alphanumeric Postfix queue ID is required") }
 ctx, cancel := context.WithTimeout(ctx, commandTimeout)
 defer cancel()
 return invoke(ctx, postsuperPath, []string{"-H", args[0]})
}

// safePostfixDiagnostic strips terminal controls and line breaks from
// untrusted child output before it reaches service logs or administrators.
func safePostfixDiagnostic(raw []byte) string {
 var out strings.Builder
 for len(raw) > 0 {
  r, size := utf8.DecodeRune(raw)
  raw = raw[size:]
  // Strip complete ANSI control sequences rather than leaving their
  // printable parameters in operator-visible diagnostics.
  if r == 0x1b {
   if len(raw) > 0 && raw[0] == '[' {
    raw = raw[1:]
    for len(raw) > 0 {
     c := raw[0]
     raw = raw[1:]
     if c >= 0x40 && c <= 0x7e { break }
     if c < 0x20 || c > 0x3f { break }
    }
   } else if len(raw) > 0 && raw[0] == ']' {
    raw = raw[1:]
    for len(raw) > 0 {
     if raw[0] == 0x07 { raw = raw[1:]; break }
     if len(raw) > 1 && raw[0] == 0x1b && raw[1] == '\\' { raw = raw[2:]; break }
     raw = raw[1:]
    }
   } else if len(raw) > 0 { raw = raw[1:] }
   out.WriteByte(' ')
   continue
  }
  if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
   out.WriteByte(' ')
   continue
  }
  out.WriteRune(r)
 }
 return strings.Join(strings.Fields(out.String()), " ")
}

// runPostsuperCommand keeps all output bounded and never interprets shell input.
func runPostsuperCommand(ctx context.Context, name string, args []string, stdoutSink io.Writer) error {
 cmd := exec.CommandContext(ctx, name, args...)
 // Isolate the command and any descendants so cancellation cannot leave
 // inherited output pipes open or orphan privileged subprocesses.
 cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
 cmd.Cancel = func() error {
  if cmd.Process == nil { return os.ErrProcessDone }
  err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
  if errors.Is(err, syscall.ESRCH) { return os.ErrProcessDone }
  return err
 }
 cmd.WaitDelay = time.Second
 cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
 budget := &outputBudget{remaining: maxOutput}
 stdout := &boundedOutput{budget: budget}
 stderr := &boundedOutput{budget: budget}
 cmd.Stdout, cmd.Stderr = stdout, stderr
 err := cmd.Run()
 // os/exec may wrap a pipe-copy error or return the child exit status
 // instead of the writer's sentinel. Check the shared budget directly.
 budget.mu.Lock()
 exceeded := budget.exceeded
 budget.mu.Unlock()
 if exceeded { return fmt.Errorf("postsuper -H output limit exceeded: %w", errOutputLimit) }
 if ctx.Err() != nil { return fmt.Errorf("postsuper -H interrupted: %w", ctx.Err()) }
 if err != nil {
  if errors.Is(err, errOutputLimit) { return fmt.Errorf("postsuper -H output limit exceeded: %w", errOutputLimit) }
  // Never expose arbitrary command output on failure. The bounded diagnostic
  // remains available, but it must not be treated as successful release.
  return fmt.Errorf("postsuper -H failed: %w: %s", err, safePostfixDiagnostic(stderr.data))
 }
 _, err = io.WriteString(stdoutSink, safePostfixDiagnostic(append(append([]byte(nil), stdout.data...), append([]byte(" "), stderr.data...)...))+"\n")
 return err
}

func executePostsuper(ctx context.Context, name string, args []string) error {
 return runPostsuperCommand(ctx, name, args, os.Stdout)
}

func main() {
 if err := runWith(context.Background(), os.Args[1:], os.Geteuid(), executePostsuper); err != nil {
  fmt.Fprintln(os.Stderr, "SpamGate Postfix release refused:", err)
  os.Exit(1)
 }
}
