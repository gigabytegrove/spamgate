package backup

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gigabytegrove/spamgate/internal/spooljson"
)

// Backup validation must not certify a new-format counter snapshot whose
// permanent initialization marker is absent. Legacy snapshots without the
// witness remain restorable for controlled upgrade compatibility.
const maxPolicyWitnessBytes = 16 << 20

func decodePolicyWitness(r io.Reader) (bool, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxPolicyWitnessBytes+1))
	if err != nil { return false, err }
	if len(raw) > maxPolicyWitnessBytes { return false, errors.New("delivery policy backup state exceeds size limit") }
	if err := spooljson.Validate(raw); err != nil {
		return false, fmt.Errorf("ambiguous delivery policy backup state: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return false, errors.New("invalid delivery policy backup state JSON")
	}
	for key := range fields {
		switch key {
		case "initialized", "greylist", "rates":
		default:
			return false, errors.New("unexpected delivery policy backup state field")
		}
	}
	value, exists := fields["initialized"]
	if !exists { return false, nil }
	if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return false, errors.New("invalid null delivery policy initialization witness")
	}
	var witnessed bool
	if err := json.Unmarshal(value, &witnessed); err != nil {
		return false, errors.New("invalid delivery policy initialization witness type")
	}
	return witnessed, nil
}

func verifySourcePolicyWitness(source string, hasMarker bool) error {
	if hasMarker {
		if err := verifySourcePolicyMarker(source); err != nil {
			return err
		}
	}
	path := filepath.Join(source, "delivery-policy.json")
	before, err := os.Lstat(path)
	if err != nil { return err }
	if !before.Mode().IsRegular() { return errors.New("delivery policy backup state is not regular") }
	f, err := os.Open(path)
	if err != nil { return err }
	defer f.Close()
	opened, err := f.Stat()
	if err != nil { return err }
	if !os.SameFile(before, opened) { return errors.New("delivery policy backup state changed during open") }
	witnessed, err := decodePolicyWitness(f)
	if err != nil { return err }
	if witnessed && !hasMarker {
		return errors.New("witnessed delivery policy state without initialization marker; refusing backup")
	}
	return nil
}

func verifyArchivePolicyWitness(files map[string]*zip.File) error {
	if err := verifyArchivePolicyMarker(files); err != nil {
		return err
	}
	state, exists := files["delivery-policy.json"]
	if !exists { return nil }
	r, err := state.Open()
	if err != nil { return err }
	witnessed, decodeErr := decodePolicyWitness(r)
	closeErr := r.Close()
	if decodeErr != nil { return decodeErr }
	if closeErr != nil { return closeErr }
	if witnessed {
		if _, ok := files[".delivery-policy.initialized"]; !ok {
			return errors.New("backup contains witnessed delivery policy state without initialization marker")
		}
	}
	return nil
}
