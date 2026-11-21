package main

import (
 "bytes"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func TestQueueLimitFailures(t *testing.T) {
 states := map[string]int{"queued": 4, "dead": 2, "delivered": 99}
 tests := []struct {
  name string
  queued, dead, pending int
  want []string
 }{
  {"disabled", -1, -1, -1, nil},
  {"inclusive", 4, 2, 3, nil},
  {"queued", 3, -1, -1, []string{"queued=4 exceeds max-queued=3"}},
  {"dead", -1, 1, -1, []string{"dead=2 exceeds max-dead=1"}},
  {"pending", -1, -1, 2, []string{"pending=3 exceeds max-pending=2"}},
  {"all", 0, 0, 0, []string{"queued=4 exceeds max-queued=0", "dead=2 exceeds max-dead=0", "pending=3 exceeds max-pending=0"}},
 }
 for _, tt := range tests {
  t.Run(tt.name, func(t *testing.T) {
   got := queueLimitFailures(states, 3, tt.queued, tt.dead, tt.pending)
   if len(got) != len(tt.want) { t.Fatalf("got %v want %v", got, tt.want) }
   for i := range got { if got[i] != tt.want[i] { t.Fatalf("got %v want %v", got, tt.want) } }
  })
 }
}

func TestQueueThresholdCLIValidation(t *testing.T) {
 dir := filepath.Join(t.TempDir(), "delivery-queue")
 if err := os.Mkdir(dir, 0700); err != nil { t.Fatal(err) }
 var out, errs bytes.Buffer
 if code := run([]string{"-dir", dir, "-max-queued=0", "-max-dead=0", "-max-pending=0", "-json"}, &out, &errs); code != 0 {
  t.Fatalf("empty queue must pass: code=%d stdout=%s stderr=%s", code, out.String(), errs.String())
 }
 out.Reset(); errs.Reset()
 if code := run([]string{"-dir", dir, "-max-dead=-2"}, &out, &errs); code != 2 || !strings.Contains(errs.String(), "nonnegative") {
  t.Fatalf("invalid limit: code=%d stderr=%s", code, errs.String())
 }
 out.Reset(); errs.Reset()
 if err := os.WriteFile(filepath.Join(dir, ".pending-incomplete"), []byte("invalid"), 0600); err != nil { t.Fatal(err) }
 if code := run([]string{"-dir", dir, "-max-pending=0", "-json"}, &out, &errs); code != 1 || !strings.Contains(errs.String(), "pending=1 exceeds max-pending=0") {
  t.Fatalf("pending gate: code=%d stdout=%s stderr=%s", code, out.String(), errs.String())
 }
}
