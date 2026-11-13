package transport

import (
    "fmt"

    "github.com/gigabytegrove/spamgate/internal/core"
)

// validateRelayOriginal distinguishes deterministic spool corruption from
// transient relay errors without requiring network access. It does not alter
// the accepted original or infer any upstream capability.
func validateRelayOriginal(m core.Message, raw []byte) error {
    if err := validateRelayEnvelope(m); err != nil {
        return fmt.Errorf("envelope: %w", err)
    }
    if err := validateRelayWireData(raw); err != nil {
        return fmt.Errorf("message framing: %w", err)
    }
    if _, err := inspectRelayHeader(raw); err != nil {
        return fmt.Errorf("header encoding: %w", err)
    }
    return nil
}
