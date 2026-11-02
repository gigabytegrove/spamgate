package transport

import (
	"errors"
	"slices"
)

// validateSpoolScanEnvelope rejects internally inconsistent durable evidence.
// The SMTP envelope and original are authoritative. The scan is an optional
// legacy-compatible snapshot, but when present it must describe that exact
// message. Matching the ID alone is insufficient: a stale or cross-recipient
// scan must never be reconstructed into an operator history entry.
func validateSpoolScanEnvelope(rec spoolRecord) error {
	if rec.Scan == nil {
		return nil
	}
	if rec.Scan.ID != rec.ID ||
		rec.Scan.Sender != rec.Sender ||
		!slices.Equal(rec.Scan.Recipients, rec.Recipients) {
		return errors.New("persisted scan envelope differs from durable SMTP original")
	}
	return nil
}
