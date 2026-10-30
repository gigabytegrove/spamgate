package core

// In-process scan performance measurements. These are actual executions, not
// retained-history estimates, and do not persist any user/message identifiers.

import (
	"sync"
	"time"
)

type ScanTelemetry struct {
	Started            time.Time
	Total              uint64
	Errors             uint64
	ByAction           map[string]uint64
	ByConnector        map[string]uint64
	DurationSecondsSum float64
	DurationBuckets    [7]uint64
	DetectionMessages map[string]uint64
}

var scanMetrics struct {
	sync.Mutex
	value ScanTelemetry
}

func observeScan(connector, action string, elapsed time.Duration, failed bool) {
	scanMetrics.Lock()
	defer scanMetrics.Unlock()
	v := &scanMetrics.value
	if v.Started.IsZero() {
		v.Started = time.Now().UTC()
	}
	v.Total++
	if failed {
		v.Errors++
	}
	switch connector {
	case "milter", "smtp", "simulation", "rspamd-http", "rspamd", "controller":
	default:
		connector = "other"
	}
	if connector == "" {
		connector = "other"
	}
	if v.ByConnector == nil {
		v.ByConnector = map[string]uint64{}
	}
	v.ByConnector[connector]++
	if failed {
		action = "error"
	}
	switch action {
	case "accept", "tag", "quarantine", "reject", "soft_reject", "error":
	default:
		action = "other"
	}
	if v.ByAction == nil {
		v.ByAction = map[string]uint64{}
	}
	v.ByAction[action]++
	seconds := elapsed.Seconds()
	v.DurationSecondsSum += seconds
	for i, threshold := range []float64{0.005, 0.02, 0.1, 0.25, 1, 5} {
		if seconds <= threshold {
			v.DurationBuckets[i]++
		}
	}
	v.DurationBuckets[6]++
}

// Only these fixed symbols can become metric labels. Never expose attacker-
// controlled finding details, subjects, domains, or recipient addresses.
func RuntimeDetectionSymbols() []string {
    return []string{
        "ARCHIVE_EXECUTABLE_CONTENT", "ARCHIVE_EXPANSION_RISK",
        "ARCHIVE_TRAVERSAL_NAME", "ARCHIVE_RISKY_MEMBER", "ARCHIVE_SYMLINK",
        "MIME_UNREADABLE", "MIME_LIMIT", "PHISHING_VISIBLE_LINK", "CLAMAV_MALWARE",
    }
}

// Count messages, not individual duplicate findings, for each allowed symbol.
// These are process-lifetime operational counters, not retained history.
func observeDetectionFindings(findings []Finding) {
    if len(findings) == 0 { return }
    allowed := map[string]bool{}
    for _, symbol := range RuntimeDetectionSymbols() { allowed[symbol] = true }
    seen := map[string]bool{}
    for _, f := range findings {
        if allowed[f.Symbol] { seen[f.Symbol] = true }
    }
    if len(seen) == 0 { return }
    scanMetrics.Lock()
    defer scanMetrics.Unlock()
    if scanMetrics.value.DetectionMessages == nil {
        scanMetrics.value.DetectionMessages = map[string]uint64{}
    }
    for symbol := range seen { scanMetrics.value.DetectionMessages[symbol]++ }
}

func RuntimeScanTelemetry() ScanTelemetry {
	scanMetrics.Lock()
	defer scanMetrics.Unlock()
	v := scanMetrics.value
	v.ByAction = make(map[string]uint64, len(scanMetrics.value.ByAction))
	for k, n := range scanMetrics.value.ByAction {
		v.ByAction[k] = n
	}
	v.ByConnector = make(map[string]uint64, len(scanMetrics.value.ByConnector))
	for k, n := range scanMetrics.value.ByConnector {
		v.ByConnector[k] = n
	}
	v.DetectionMessages = make(map[string]uint64, len(scanMetrics.value.DetectionMessages))
    for k, n := range scanMetrics.value.DetectionMessages {
        v.DetectionMessages[k] = n
    }
	return v
}
