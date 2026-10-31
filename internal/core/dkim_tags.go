package core

import (
	"errors"
	"strings"
)

// dkimParseTagsStrict is used on security-sensitive signature and DNS key
// records. A map-only parser silently overwrites duplicate tags, which can
// make different verifiers interpret the same signature differently.
func dkimParseTagsStrict(input string) (map[string]string, error) {
	tags := make(map[string]string)
	parts := strings.Split(input, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" && i == len(parts)-1 {
			continue // RFC permits a final semicolon
		}
		if part == "" {
			return tags, errors.New("empty DKIM tag")
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			return tags, errors.New("DKIM tag missing equals sign")
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		if key == "" || key[0] < 'a' || key[0] > 'z' {
			return tags, errors.New("invalid DKIM tag name")
		}
		for _, c := range key[1:] {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
				return tags, errors.New("invalid DKIM tag name")
			}
		}
		if _, exists := tags[key]; exists {
			return tags, errors.New("duplicate DKIM tag " + key)
		}
		if value == "" {
			// An empty b= is permitted only while constructing a signature,
			// not when verifying an incoming message.
			if key != "b" {
				return tags, errors.New("empty DKIM tag " + key)
			}
		}
		tags[key] = value
	}
	return tags, nil
}

func dkimListContains(list, item string) bool {
	for _, entry := range strings.Split(list, ":") {
		if strings.EqualFold(strings.TrimSpace(entry), item) {
			return true
		}
	}
	return false
}
