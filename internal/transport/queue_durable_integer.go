package transport

import (
	"errors"
	"strconv"
)

// strictDurableNonnegativeInteger accepts only canonical unquoted JSON
// integers in the signed 64-bit nonnegative range. Recovery must reject
// ambiguous or overflowing representations without echoing private data.
func strictDurableNonnegativeInteger(raw []byte) (int64, error) {
	// A signed 64-bit nonnegative integer has at most 19 decimal digits.
	// Reject oversized corrupt metadata before allocating a string or parsing.
	if len(raw) > 19 {
		return 0, errors.New("durable integer exceeds signed range")
	}
	if len(raw) == 0 || raw[0] < '0' || raw[0] > '9' {
		return 0, errors.New("invalid durable nonnegative integer")
	}
	if len(raw) > 1 && raw[0] == '0' {
		return 0, errors.New("noncanonical durable integer")
	}
	for _, b := range raw {
		if b < '0' || b > '9' {
			return 0, errors.New("invalid durable integer syntax")
		}
	}
	value, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, errors.New("durable integer exceeds signed range")
	}
	return value, nil
}
