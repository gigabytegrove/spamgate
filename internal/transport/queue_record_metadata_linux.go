//go:build linux

package transport

import (
	"errors"
	"fmt"
	"os"
)

// validateSpoolMetadata verifies the inspected original still occupies the
// pathname and has not changed in place. Do not rely on inode identity alone:
// a same-inode rewrite can retain the same name and file size.
func validateSpoolMetadata(path string, inspected os.FileInfo) error {
	if inspected == nil || !inspected.Mode().IsRegular() {
		return errors.New("spool inspection must be a regular file")
	}
	current, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect spool pathname: %w", err)
	}
	if err := validateOpenedQueueRecordMetadata(current); err != nil {
		return fmt.Errorf("unsafe spool original: %w", err)
	}
	if !sameQueueRecordSnapshot(inspected, current) {
		return errors.New("spool original identity or contents changed since inspection")
	}
	return nil
}
