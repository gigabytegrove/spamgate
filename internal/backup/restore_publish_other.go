//go:build !linux || (!amd64 && !arm64)

package backup

import (
	"errors"
	"os"
	"runtime"
)

// Windows rename refuses an existing destination. Unsupported Linux
// architectures fail closed until a tested RENAME_NOREPLACE implementation
// is provided; never silently fall back to overwrite-capable os.Rename.
func publishRestoredDirectory(stage, dest string) error {
	if runtime.GOOS == "linux" {
		return errors.New("atomic no-replace restore is unsupported on this Linux architecture")
	}
	return os.Rename(stage, dest)
}
