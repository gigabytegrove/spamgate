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
	return v
}
