package backup

import (
    "bytes"
    "encoding/json"
    "fmt"

    "github.com/gigabytegrove/spamgate/internal/spooljson"
)

// decodeBackupManifest refuses ambiguous JSON before any backup is trusted.
// encoding/json silently accepts duplicate object keys, case-insensitive
// aliases of Go struct fields, invalid surrogate escapes and unknown fields.
// An attacker could otherwise supply a manifest with contradictory evidence
// whose interpreted values depend on the JSON reader. Version 1 manifests
// have a fixed schema; additional fields require a new explicit format.
func decodeBackupManifest(data []byte, manifest *Manifest) error {
    if err := spooljson.Validate(data); err != nil {
        return fmt.Errorf("backup manifest JSON integrity: %w", err)
    }
    decoder := json.NewDecoder(bytes.NewReader(data))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(manifest); err != nil {
        return fmt.Errorf("invalid backup manifest schema: %w", err)
    }
    if err := validateManifestSemantics(*manifest); err != nil {
        return fmt.Errorf("invalid backup manifest evidence: %w", err)
    }
    return nil
}
