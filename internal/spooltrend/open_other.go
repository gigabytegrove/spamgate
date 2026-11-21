//go:build !linux

package spooltrend

import "os"

// Non-Linux platforms retain the original identity-checked read path.
// The Linux-only no-follow guarantee must not be inferred on these systems.
func openEvidence(path string) (*os.File, error) {
 return os.Open(path)
}
