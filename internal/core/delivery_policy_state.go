package core

// Persisted greylist and rate-limit counters are enforcement evidence, not
// advisory cache data. Refuse ambiguous or oversized state at startup rather
// than silently resetting an active policy or accepting a last-key-wins JSON
// document. The original file is never rewritten by this decoder.
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gigabytegrove/spamgate/internal/spooljson"
)

const (
	maxDeliveryPolicyFileBytes int64 = 16 << 20
	maxDeliveryPolicyKeys            = 20000
	maxDeliveryPolicyRateStamps      = 200000
	maxDeliveryPolicyStampsPerKey    = 100000
)

func validDeliveryPolicyKey(key string) bool {
	if len(key) != 64 || strings.ToLower(key) != key {
		return false
	}
	_, err := hex.DecodeString(key)
	return err == nil
}

func readDeliveryPolicyState(path string) (deliveryPolicyState, error) {
	var empty deliveryPolicyState
	before, err := os.Lstat(path)
	if err != nil {
		return empty, err
	}
	if !before.Mode().IsRegular() {
		return empty, errors.New("delivery policy state is not a regular file")
	}
	if before.Size() > maxDeliveryPolicyFileBytes {
		return empty, errors.New("delivery policy state exceeds size limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return empty, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return empty, errors.New("delivery policy state changed during open")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxDeliveryPolicyFileBytes+1))
	if err != nil {
		return empty, err
	}
	if int64(len(raw)) > maxDeliveryPolicyFileBytes {
		return empty, errors.New("delivery policy state exceeds size limit")
	}
	if err := spooljson.Validate(raw); err != nil {
		return empty, fmt.Errorf("ambiguous delivery policy state: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var state deliveryPolicyState
	if err := decoder.Decode(&state); err != nil {
		return empty, errors.New("delivery policy state has invalid schema or timestamp")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return empty, errors.New("delivery policy state has trailing data")
	}
	if state.Greylist == nil {
		state.Greylist = make(map[string]time.Time)
	}
	if state.Rates == nil {
		state.Rates = make(map[string][]time.Time)
	}
	if len(state.Greylist) > maxDeliveryPolicyKeys || len(state.Rates) > maxDeliveryPolicyKeys {
		return empty, errors.New("delivery policy state exceeds key capacity")
	}
	for key, stamp := range state.Greylist {
		if !validDeliveryPolicyKey(key) || stamp.IsZero() {
			return empty, errors.New("delivery policy state has invalid greylist key or timestamp")
		}
	}
	total := 0
	for key, stamps := range state.Rates {
		if !validDeliveryPolicyKey(key) || stamps == nil || len(stamps) > maxDeliveryPolicyStampsPerKey {
			return empty, errors.New("delivery policy state has invalid rate key or count")
		}
		total += len(stamps)
		if total > maxDeliveryPolicyRateStamps {
			return empty, errors.New("delivery policy state exceeds timestamp capacity")
		}
		for _, stamp := range stamps {
			if stamp.IsZero() {
				return empty, errors.New("delivery policy state has invalid rate timestamp")
			}
		}
	}
	return state, nil
}
