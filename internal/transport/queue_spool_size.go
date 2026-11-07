package transport

import "errors"

// maxDurableSpoolRecordBytes is the on-disk JSON record limit enforced by
// readSpoolFile. Writers must enforce the same limit before publishing a
// record or acknowledging an SMTP transaction.
const maxDurableSpoolRecordBytes = 20 << 20

func validateEncodedSpoolSize(encodedBytes int) error {
	if encodedBytes < 2 || encodedBytes > maxDurableSpoolRecordBytes {
		return errors.New("encoded delivery spool record exceeds recovery size limit")
	}
	return nil
}
