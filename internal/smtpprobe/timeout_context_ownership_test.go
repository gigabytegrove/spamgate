package smtpprobe

import (
 "context"
 "errors"
 "testing"
 "time"
)

func TestProbeTimeoutContextCancellationOwnership(t *testing.T) {
 parent := context.Background()
 ctx, cancel := probeTimeoutContext(parent, time.Minute)
 cancel()
 select {
 case <-ctx.Done():
 case <-time.After(time.Second):
  t.Fatal("cancellation did not close Done")
 }
 if !errors.Is(ctx.Err(), context.Canceled) {
  t.Fatalf("cancellation cause = %v", ctx.Err())
 }
}

func TestProbeTimeoutContextDeadline(t *testing.T) {
 ctx, cancel := probeTimeoutContext(context.Background(), time.Millisecond)
 defer cancel()
 select {
 case <-ctx.Done():
 case <-time.After(time.Second):
  t.Fatal("deadline did not close Done")
 }
 if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
  t.Fatalf("deadline cause = %v", ctx.Err())
 }
}

func TestProbePreflightDoesNotCreateTimeoutContext(t *testing.T) {
 result, err := Probe(context.Background(), Options{Timeout: 0})
 if err == nil { t.Fatal("expected timeout configuration failure") }
 if result.FailureStage != "configuration" {
  t.Fatalf("failure stage = %q", result.FailureStage)
 }
 if result.ProbeDurationMillis < 0 {
  t.Fatalf("invalid probe duration = %d", result.ProbeDurationMillis)
 }
}
