package updater

import (
 "context"
 "errors"
 "fmt"
 "os/exec"
 "time"
)

const executableProbeOutputLimit = 4096

// executableProbeOutput retains only bounded stdout from a candidate binary.
// An untrusted worker must not allocate unlimited memory during qualification.
type executableProbeOutput struct {
 data []byte
 overflow bool
}

func (w *executableProbeOutput) Write(p []byte) (int, error) {
 available := executableProbeOutputLimit - len(w.data)
 if available < len(p) { w.overflow = true }
 if available > 0 {
  n := len(p)
  if n > available { n = available }
  w.data = append(w.data, p[:n]...)
 }
 return len(p), nil
}

// A normal nonzero exit is returned to the caller, which may interpret only
// a silent unsupported -build-version flag as a legacy unversioned worker.
// The timeout also bounds child processes that retain inherited stdout pipes.
func probeExecutableFlag(path, flag string) (string, error) {
 ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
 defer cancel()
 cmd := exec.CommandContext(ctx, path, flag)
 cmd.WaitDelay = time.Second
 var output executableProbeOutput
 cmd.Stdout = &output
 cmd.Stderr = nil
 err := cmd.Run()
 if ctx.Err() != nil {
  return "", fmt.Errorf("executable %s probe timed out: %w", flag, ctx.Err())
 }
 if output.overflow {
  return "", fmt.Errorf("executable %s probe exceeded %d output bytes", flag, executableProbeOutputLimit)
 }
 if errors.Is(err, exec.ErrWaitDelay) {
  return "", fmt.Errorf("executable %s probe left open output pipes: %w", flag, err)
 }
 return string(output.data), err
}
