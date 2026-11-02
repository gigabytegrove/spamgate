package main

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"

    "github.com/gigabytegrove/spamgate/internal/spooljson"
)

// corpusRecord deliberately contains no message content or identifying metadata.
// The evaluator accepts only exact, documented field names, never Go's
// case-insensitive struct field aliases or null-to-empty string coercions.
type corpusRecord struct {
    Label string
    Action string
    Cohort string
    ID string
}

func parseCorpusRecord(raw []byte) (corpusRecord, error) {
    var result corpusRecord
    if len(raw) > 64<<10 {
        return result, errors.New("corpus record exceeds 64 KiB")
    }
    // encoding/json silently accepts duplicate keys and invalid UTF-8.
    // Validate also catches escaped Unicode aliases and unpaired surrogates.
    if err := spooljson.Validate(raw); err != nil {
        return result, fmt.Errorf("ambiguous or malformed corpus JSON: %w", err)
    }
    var fields map[string]json.RawMessage
    if err := json.Unmarshal(raw, &fields); err != nil {
        return result, errors.New("corpus object cannot be decoded")
    }
    if len(fields) < 2 || len(fields) > 4 {
        return result, errors.New("corpus requires label and action with at most two optional fields")
    }
    for key, rawValue := range fields {
        var target *string
        switch key {
        case "label":
            target = &result.Label
        case "action":
            target = &result.Action
        case "cohort":
            target = &result.Cohort
        case "id":
            target = &result.ID
        default:
            return corpusRecord{}, errors.New("corpus contains an unsupported field name")
        }
        if bytes.Equal(bytes.TrimSpace(rawValue), []byte("null")) {
            return corpusRecord{}, errors.New("corpus field must be a JSON string, not null")
        }
        if err := json.Unmarshal(rawValue, target); err != nil {
            return corpusRecord{}, errors.New("corpus field must be a JSON string")
        }
    }
    if _, ok := fields["label"]; !ok {
        return corpusRecord{}, errors.New("corpus label field is required")
    }
    if _, ok := fields["action"]; !ok {
        return corpusRecord{}, errors.New("corpus action field is required")
    }
    return result, nil
}
