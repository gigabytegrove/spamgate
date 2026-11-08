//go:build linux

package main

import (
	"context"
	"errors"
	"strings"
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
