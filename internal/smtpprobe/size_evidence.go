package smtpprobe

import (
	"strconv"
	"strings"
)

// sizeEvidence extracts RFC 1870 SIZE limits. The EHLO identity line is not
// an extension. Ambiguous, malformed or duplicate SIZE advertisements never
// produce a trusted numeric limit.
func sizeEvidence(lines []string) (advertised, known bool, limit uint64, warning string) {
	if len(lines) < 2 {
		return false, false, 0, ""
	}
	count := 0
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		keyword := strings.ToUpper(fields[0])
		if !sizeKeywordCandidate(keyword) {
			continue
		}
		advertised = true
		count++
		if count > 1 {
			warning = "DUPLICATE_SIZE_ADVERTISEMENT"
			continue
		}
		// SIZE=123 is not the RFC 1870 extension syntax. Do not silently
		// ignore it and then trust a subsequent SIZE line.
		if keyword != "SIZE" {
			warning = "MALFORMED_SIZE_ADVERTISEMENT"
			continue
		}
		if len(fields) == 1 {
			continue // SIZE without a number advertises no fixed limit.
		}
		if len(fields) != 2 {
			warning = "MALFORMED_SIZE_ADVERTISEMENT"
			continue
		}
		value := fields[1]
		if len(value) == 0 || len(value) > 20 {
			warning = "MALFORMED_SIZE_ADVERTISEMENT"
			continue
		}
		valid := true
		for i := 0; i < len(value); i++ {
			if value[i] < '0' || value[i] > '9' {
				valid = false
				break
			}
		}
		if !valid {
			warning = "MALFORMED_SIZE_ADVERTISEMENT"
			continue
		}
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			warning = "MALFORMED_SIZE_ADVERTISEMENT"
			continue
		}
		known, limit = true, n
	}
	if warning != "" {
		return advertised, false, 0, warning
	}
	return advertised, known, limit, ""
}

// sizeKeywordCandidate recognizes malformed SIZE separators as well as the
// legitimate bare keyword. A malformed declaration must not be silently
// skipped when a later valid SIZE line is present.
func sizeKeywordCandidate(keyword string) bool {
	if keyword == "SIZE" {
		return true
	}
	if !strings.HasPrefix(keyword, "SIZE") || len(keyword) == 4 {
		return false
	}
	switch keyword[4] {
	case '=', ':', ';', ',', '/', '+', '-':
		return true
	default:
		return false
	}
}
