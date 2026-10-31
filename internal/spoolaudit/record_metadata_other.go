//go:build !linux

package spoolaudit

import "os"

// The native Linux spool ownership/link contract cannot be established on
// other platforms. Structural and digest checks remain available.
func validateAuditRecordMetadata(_ string, _ os.FileInfo) error { return nil }
