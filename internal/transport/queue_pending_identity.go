package transport

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gigabytegrove/spamgate/internal/spooljson"
)

// refusePendingIdentityReuse prevents a new SMTP acknowledgement from
// publishing a queue ID already represented by a crash-retained original.
// Caller holds the cross-process intake lock and has checked spool capacity.
// Invalid pending evidence has unknown ownership, so intake fails closed until
// an operator investigates it; this function never repairs or removes mail.
func (q *DeliveryQueue) refusePendingIdentityReuse(id string) error {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return fmt.Errorf("inspect unpublished SMTP originals: %w", err)
	}
	if len(entries) > 4096 {
		return errors.New("unpublished SMTP original inspection exceeds entry limit")
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".pending-") {
			continue
		}
		path := filepath.Join(q.dir, entry.Name())
		meta, err := os.Lstat(path)
		if err != nil {
			return errors.New("unpublished SMTP original changed during identity inspection")
		}
		raw, err := readSpoolFile(path, meta)
		if err != nil {
			return errors.New("unpublished SMTP original is not safely readable; operator investigation required")
		}
		if err := spooljson.Validate(raw); err != nil {
			return errors.New("unpublished SMTP original contains invalid or ambiguous JSON; operator investigation required")
		}
		if err := validateCanonicalSpoolRecordJSON(raw); err != nil {
            return errors.New("unpublished SMTP original has ambiguous envelope identity; operator investigation required")
        }
		var rec spoolRecord
		if err := json.Unmarshal(raw, &rec); err != nil ||
			!validQueueID(rec.ID) || rec.Size < 1 || rec.Size > 10<<20 ||
			len(rec.RawRFC822) != rec.Size || len(rec.Recipients) == 0 ||
			len(rec.Recipients) > 1000 || rec.Attempts < 0 {
			return errors.New("unpublished SMTP original has an unverifiable envelope; operator investigation required")
		}
		switch rec.State {
		case "queued", "delivering", "dead", "delivered", "discard_pending":
		default:
			return errors.New("unpublished SMTP original has an invalid delivery state; operator investigation required")
		}
		if (rec.IntegritySHA256 != "" && rec.IntegritySHA256 != spoolDigest(rec)) ||
			(rec.StateSHA256 != "" && rec.StateSHA256 != spoolStateDigest(rec)) {
			return errors.New("unpublished SMTP original failed integrity verification; operator investigation required")
		}
		if err := validateSpoolScanEnvelope(rec); err != nil {
			return errors.New("unpublished SMTP original scan envelope does not match durable original; operator investigation required")
		}
		if rec.ID == id {
			return errors.New("queue ID reserved by retained unpublished SMTP original; manual investigation required")
		}
	}
	return nil
}
