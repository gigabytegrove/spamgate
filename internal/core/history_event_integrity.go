package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gigabytegrove/spamgate/internal/spooljson"
)

// decodeHistoryEvent is the common trust boundary for persisted scan history.
// Go's default JSON decoder silently accepts duplicate keys, case-insensitive
// field aliases, and malformed Unicode; none are acceptable for audit evidence.
// Unknown, non-conflicting fields remain readable for forward compatibility.
func decodeHistoryEvent(raw []byte) (Message, error) {
	var m Message
	if err := spooljson.Validate(raw); err != nil {
		return m, fmt.Errorf("ambiguous or malformed history JSON: %w", err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return Message{}, errors.New("history event has invalid field values")
	}
	if m.ID == "" {
		return Message{}, errors.New("history event has no scan ID")
	}
	return m, nil
}

// Comparing only action and timestamp can conceal a rewritten sender,
// recipient, finding, delivery status, or operator attribution. Compare the
// complete persisted JSON representation instead. Marshaling also strips
// non-persistent time.Time monotonic data and transient header snapshots.
func sameHistoryEvent(disk, retained Message) bool {
	a, err := json.Marshal(disk)
	if err != nil {
		return false
	}
	b, err := json.Marshal(retained)
	return err == nil && bytes.Equal(a, b)
}
