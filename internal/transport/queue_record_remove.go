package transport

import (
    "errors"
    "fmt"
    "os"
)

// removeRecord is used only after the caller has persisted the delivery or
// discard state and the corresponding operator/delivery audit evidence.
// Refuse an unsafe or replaced record rather than unlinking an arbitrary child.
func (q *DeliveryQueue) removeRecord(id string) error {
    if !validQueueID(id) { return errors.New("invalid queue record ID") }
    name := id + ".json"
    inspected, err := os.Lstat(q.path(id))
    if err != nil { return err }
    if err := validateSpoolMetadata(q.path(id), inspected); err != nil {
        return fmt.Errorf("unsafe queue record removal: %w", err)
    }
    return removeQueueRecordAt(q.dir, q.dirIdentity, name, inspected)
}
