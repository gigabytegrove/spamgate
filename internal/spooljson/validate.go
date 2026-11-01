package spooljson

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "unicode/utf8"
)

const (
    maxJSONDepth = 64
    maxJSONTokens = 250000
)

// Validate checks complete JSON syntax before the normal Go decoder reads a
// durable SMTP original. encoding/json accepts duplicate object keys (last
// value wins), allowing contradictory delivery state or scan evidence to
// satisfy a digest computed from the decoded struct. Never relay such records.
// The check is schema-independent for backward/forward spool compatibility.
func Validate(data []byte) error {
    if !utf8.Valid(data) {
        return errors.New("spool JSON contains invalid UTF-8")
    }
    decoder := json.NewDecoder(bytes.NewReader(data))
    decoder.UseNumber()
    budget := maxJSONTokens
    first, err := decoder.Token()
    if err != nil {
        return fmt.Errorf("read spool JSON root: %w", err)
    }
    if first != json.Delim('{') {
        return errors.New("spool JSON root must be an object")
    }
    if err := validateValue(decoder, first, 0, &budget); err != nil {
        return err
    }
    if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
        if err == nil {
            return errors.New("spool JSON contains trailing values")
        }
        return fmt.Errorf("spool JSON contains trailing invalid data: %w", err)
    }
    return nil
}

func validateValue(decoder *json.Decoder, value json.Token, depth int, budget *int) error {
    *budget--
    if *budget < 0 {
        return errors.New("spool JSON token budget exceeded")
    }
    delimiter, isContainer := value.(json.Delim)
    if !isContainer {
        return nil
    }
    if depth >= maxJSONDepth {
        return errors.New("spool JSON nesting depth exceeded")
    }
    switch delimiter {
    case '{':
        seen := make(map[string]struct{})
        for decoder.More() {
            keyToken, err := decoder.Token()
            if err != nil {
                return fmt.Errorf("read spool JSON object key: %w", err)
            }
            key, ok := keyToken.(string)
            if !ok {
                return errors.New("spool JSON object key is not a string")
            }
            *budget--
            if *budget < 0 {
                return errors.New("spool JSON token budget exceeded")
            }
            folded := foldJSONKey(key)
            if _, duplicate := seen[folded]; duplicate {
                return errors.New("spool JSON contains duplicate object key")
            }
            seen[folded] = struct{}{}
            child, err := decoder.Token()
            if err != nil {
                return fmt.Errorf("read spool JSON object value: %w", err)
            }
            if err := validateValue(decoder, child, depth+1, budget); err != nil {
                return err
            }
        }
        end, err := decoder.Token()
        if err != nil || end != json.Delim('}') {
            return errors.New("spool JSON object is not closed")
        }
    case '[':
        for decoder.More() {
            child, err := decoder.Token()
            if err != nil {
                return fmt.Errorf("read spool JSON array value: %w", err)
            }
            if err := validateValue(decoder, child, depth+1, budget); err != nil {
                return err
            }
        }
        end, err := decoder.Token()
        if err != nil || end != json.Delim(']') {
            return errors.New("spool JSON array is not closed")
        }
    default:
        return errors.New("unexpected spool JSON delimiter")
    }
    return nil
}
