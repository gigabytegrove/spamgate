package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"

	"github.com/gigabytegrove/spamgate/internal/spooljson"
)

const postfixReleaseRequestLimit = 16 << 10

type postfixReleaseRequest struct {
	QueueID string `json:"queue_id"`
	Confirm string `json:"confirm"`
	Reason  string `json:"reason"`
}

// This request authorizes an irreversible privileged MTA operation. The
// ordinary API decoder accepts duplicate keys through encoding/json. Reject
// conflicting, escaped, case-folded and trailing JSON before any audit or
// postsuper action can occur. Bound reads independently of Content-Length.
func decodePostfixReleaseRequest(r *http.Request) (postfixReleaseRequest, error) {
	var request postfixReleaseRequest
	if r.Body == nil {
		return request, errors.New("missing release request")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, postfixReleaseRequestLimit+1))
	if err != nil {
		return request, errors.New("cannot read release request")
	}
	if len(raw) > postfixReleaseRequestLimit {
		return request, errors.New("release request exceeds size limit")
	}
	if err := spooljson.Validate(raw); err != nil {
		return request, errors.New("ambiguous or malformed release request")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return postfixReleaseRequest{}, errors.New("invalid release request fields")
	}
	return request, nil
}

func validPostfixReleaseReason(reason string) bool {
	if len(reason) > 512 || len(strings.TrimSpace(reason)) < 12 {
		return false
	}
	for _, r := range reason {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}
