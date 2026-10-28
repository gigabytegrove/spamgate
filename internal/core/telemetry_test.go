package core

import (
	"sync"
	"testing"
	"time"
)

func TestRuntimeTelemetryConcurrentAndPrivacySafe(t *testing.T) {
	start := RuntimeScanTelemetry()
	var jobs sync.WaitGroup
	for i := 0; i < 100; i++ {
		jobs.Add(1)
		go func() { defer jobs.Done(); observeScan("milter", "tag", 20*time.Millisecond, false) }()
	}
	jobs.Wait()
	got := RuntimeScanTelemetry()
	if got.Total-start.Total != 100 || got.ByAction["tag"]-start.ByAction["tag"] != 100 || got.ByConnector["milter"]-start.ByConnector["milter"] != 100 {
		t.Fatalf("telemetry lost concurrent events: %+v", got)
	}
	for _, v := range got.DurationBuckets {
		if v > got.Total {
			t.Fatalf("histogram exceeded scan total: %+v", got)
		}
	}
	got.ByAction["tag"] = 0
	if RuntimeScanTelemetry().ByAction["tag"] == 0 {
		t.Fatal("returned mutable shared metrics map")
	}
}
