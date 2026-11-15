//go:build !linux

package backup

import "os"

// Non-Linux verification retains its existing path-based checks.
// Native Linux is the production security target.
func openRestoredRegularNoFollow(path string) (*os.File, error) {
 return os.Open(path)
}
