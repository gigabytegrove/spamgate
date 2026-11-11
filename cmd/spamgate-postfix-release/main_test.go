//go:build linux

package main

import (
	"context"
	"errors"
	"strings"
 "sync"
	"testing"
	"time"
)

func TestReleaseHelperRejectsUnprivilegedAndUnsafeRequests(t *testing.T) {
	cases := [][]string{nil, {}, {""}, {"-H"}, {"ALL"}, {"A123", "B456"}, {"A123;id"}, {"A123\nB456"}, {"../../etc/passwd"}, {strings.Repeat("A", 33)}, {"A123*"}}
	for _, args := range cases {
		called := false
		err := runWith(context.Background(), args, 0, func(context.Context, string, []string) error { called = true; return nil })
		if err == nil || called {
			t.Errorf("accepted unsafe args %q: %v", args, err)
		}
	}
	called := false
	if err := runWith(context.Background(), []string{"A123"}, 1000, func(context.Context, string, []string) error { called = true; return nil }); err == nil || called {
		t.Fatal("unprivileged helper executed Postfix")
	}
}

func TestReleaseHelperExecutesOnlyFixedPostsuperHold(t *testing.T) {
	for _, id := range []string{"A1234", "ab01234", strings.Repeat("F", 32)} {
		calls := 0
		err := runWith(context.Background(), []string{id}, 0, func(ctx context.Context, path string, args []string) error {
			calls++
			if path != postsuperPath || len(args) != 2 || args[0] != "-H" || args[1] != id {
				t.Fatalf("unsafe command %q %q", path, args)
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > commandTimeout {
				t.Fatal("missing bounded command deadline")
			}
			return nil
		})
		if err != nil || calls != 1 {
			t.Fatalf("command failed: %v, calls=%d", err, calls)
		}
	}
}

func TestReleaseHelperPropagatesPostfixError(t *testing.T) {
	expected := errors.New("postsuper failure")
	err := runWith(context.Background(), []string{"A123"}, 0, func(context.Context, string, []string) error { return expected })
	if !errors.Is(err, expected) {
		t.Fatalf("Postfix failure hidden: %v", err)
	}
}

func TestBoundedPostfixOutput(t *testing.T) {
	b := &boundedOutput{limit: 4}
	if n, err := b.Write([]byte("abcd")); n != 4 || err != nil {
		t.Fatalf("first write: %d %v", n, err)
	}
	if n, err := b.Write([]byte("x")); n != 0 || err == nil {
		t.Fatalf("overflow accepted: %d %v", n, err)
	}
	if string(b.data) != "abcd" {
		t.Fatalf("output changed on overflow: %q", b.data)
	}
}

func TestSharedPostfixOutputBudget(t *testing.T) {
	budget := &outputBudget{remaining: 8}
	stdout := &boundedOutput{budget: budget}
	stderr := &boundedOutput{budget: budget}
	if n, err := stdout.Write([]byte("12345")); n != 5 || err != nil {
		t.Fatalf("stdout: n=%d err=%v", n, err)
	}
	if n, err := stderr.Write([]byte("678")); n != 3 || err != nil {
		t.Fatalf("stderr: n=%d err=%v", n, err)
	}
	if n, err := stdout.Write([]byte("9")); n != 0 || err == nil {
		t.Fatalf("combined output limit bypassed: n=%d err=%v", n, err)
	}
	if budget.remaining != 0 || string(stdout.data) != "12345" || string(stderr.data) != "678" {
		t.Fatalf("overflow corrupted buffered output: remaining=%d stdout=%q stderr=%q", budget.remaining, stdout.data, stderr.data)
	}
}

func TestSharedPostfixOutputBudgetRejectsOversizedFirstWrite(t *testing.T) {
	budget := &outputBudget{remaining: 2}
	writer := &boundedOutput{budget: budget}
	if n, err := writer.Write([]byte("abc")); n != 0 || err == nil {
		t.Fatalf("oversized write accepted: n=%d err=%v", n, err)
	}
	if budget.remaining != 2 || len(writer.data) != 0 {
		t.Fatal("rejected write consumed budget or mutated buffer")
	}
}

func TestSharedPostfixOutputBudgetConcurrentWriters(t *testing.T) {
 budget := &outputBudget{remaining: 4096}
 stdout := &boundedOutput{budget: budget}
 stderr := &boundedOutput{budget: budget}
 const writers = 32
 const writesPerWriter = 128
 var wg sync.WaitGroup
 for i := 0; i < writers; i++ {
  wg.Add(1)
  go func(i int) {
   defer wg.Done()
   target := stdout
   if i%2 == 1 { target = stderr }
   for j := 0; j < writesPerWriter; j++ {
    if n, err := target.Write([]byte{'x'}); n != 1 || err != nil {
     t.Errorf("writer %d iteration %d: n=%d err=%v", i, j, n, err)
     return
    }
   }
  }(i)
 }
 wg.Wait()
 if budget.remaining != 0 || len(stdout.data) != 2048 || len(stderr.data) != 2048 {
  t.Fatalf("concurrent budget mismatch: remaining=%d stdout=%d stderr=%d", budget.remaining, len(stdout.data), len(stderr.data))
 }
 if n, err := stdout.Write([]byte{'x'}); n != 0 || !errors.Is(err, errOutputLimit) {
  t.Fatalf("exhausted budget bypassed: n=%d err=%v", n, err)
 }
}

func TestBoundedPostfixOutputRejectsInvalidLimit(t *testing.T) {
 b := &boundedOutput{limit: -1}
 if n, err := b.Write([]byte("x")); n != 0 || !errors.Is(err, errOutputLimit) {
  t.Fatalf("invalid limit accepted: n=%d err=%v", n, err)
 }
}

func TestReleaseHelperRefusesCanceledRequestBeforeExecution(t *testing.T) {
 ctx, cancel := context.WithCancel(context.Background())
 cancel()
 called := false
 err := runWith(ctx, []string{"A123"}, 0, func(context.Context, string, []string) error {
  called = true
  return nil
 })
 if !errors.Is(err, context.Canceled) || called {
  t.Fatalf("canceled release executed: called=%v err=%v", called, err)
 }
}

func TestReleaseHelperRefusesExpiredRequestBeforeExecution(t *testing.T) {
 ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
 defer cancel()
 called := false
 err := runWith(ctx, []string{"A123"}, 0, func(context.Context, string, []string) error {
  called = true
  return nil
 })
 if !errors.Is(err, context.DeadlineExceeded) || called {
  t.Fatalf("expired release executed: called=%v err=%v", called, err)
 }
}

func TestReleaseHelperRefusesMissingExecutorAndContext(t *testing.T) {
 if err := runWith(context.Background(), []string{"A123"}, 0, nil); err == nil {
  t.Fatal("nil executor accepted")
 }
 called := false
 err := runWith(nil, []string{"A123"}, 0, func(context.Context, string, []string) error {
  called = true
  return nil
 })
 if err == nil || called {
  t.Fatalf("nil context executed: called=%v err=%v", called, err)
 }
}
