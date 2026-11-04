//go:build !linux

package backup

import "os"

// Other platforms retain the original identity, size and mtime checks.
func sourceChangeTimeEqual(before, after os.FileInfo) bool {
    return true
}
