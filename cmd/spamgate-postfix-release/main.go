//go:build linux

// spamgate-postfix-release is an intentionally narrow privileged boundary.
// Its only operation is to ask Postfix to release one validated queue ID
// from HOLD. It never accepts command paths, options, or arbitrary actions.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const postsuperPath = "/usr/sbin/postsuper"
const commandTimeout = 8 * time.Second
const maxOutput = 8192

func validQueueID(id string) bool {
	if len(id) == 0 || len(id) > 32 || strings.EqualFold(id, "ALL") {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// boundedOutput returns an error rather than silently truncating output.
// This ensures an unexpectedly verbose postsuper response is not reported
// as a verified success.
type boundedOutput struct {
	data  []byte
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-len(b.data) {
		return 0, errors.New("Postfix command output exceeds safe limit")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

// runWith allows a fake executor in tests, but the actual executable uses
// the fixed absolute Postfix path and no shell.
func runWith(ctx context.Context, args []string, uid int, invoke func(context.Context, string, []string) error) error {
	if uid != 0 {
		return errors.New("Postfix release helper must run as root through an explicit host privilege grant")
	}
	if len(args) != 1 || !validQueueID(args[0]) {
		return errors.New("exactly one alphanumeric Postfix queue ID is required")
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	return invoke(ctx, postsuperPath, []string{"-H", args[0]})
}

func executePostsuper(ctx context.Context, name string, args []string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	stdout := &boundedOutput{limit: maxOutput}
	stderr := &boundedOutput{limit: maxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		// Postfix errors are returned to the unprivileged caller without
		// leaking arbitrary environment or shell expansions.
		return fmt.Errorf("postsuper -H failed: %w: %s", err, strings.TrimSpace(string(stderr.data)))
	}
	_, err := io.WriteString(os.Stdout, strings.TrimSpace(string(stdout.data)+" "+string(stderr.data))+"\n")
	return err
}

func main() {
	if err := runWith(context.Background(), os.Args[1:], os.Geteuid(), executePostsuper); err != nil {
		fmt.Fprintln(os.Stderr, "SpamGate Postfix release refused:", err)
		os.Exit(1)
	}
}
