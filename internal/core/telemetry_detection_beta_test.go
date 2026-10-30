package core

import (
    "sync"
    "testing"
)

func TestBetaDetectionMetricsBoundedPrivacyAndDeduplication(t *testing.T) {
    before := RuntimeScanTelemetry()
    findings := []Finding{
        {Symbol: "ARCHIVE_EXECUTABLE_CONTENT", Detail: "user@example.org"},
        {Symbol: "ARCHIVE_EXECUTABLE_CONTENT", Detail: "duplicate"},
        {Symbol: "PHISHING_VISIBLE_LINK", Detail: "private.example.org"},
        {Symbol: "UNTRUSTED_DYNAMIC_SYMBOL", Detail: "must never be a label"},
    }
    var wg sync.WaitGroup
    for i := 0; i < 20; i++ {
        wg.Add(1)
        go func() { defer wg.Done(); observeDetectionFindings(findings) }()
    }
    wg.Wait()
    after := RuntimeScanTelemetry()
    if after.DetectionMessages["ARCHIVE_EXECUTABLE_CONTENT"]-before.DetectionMessages["ARCHIVE_EXECUTABLE_CONTENT"] != 20 {
        t.Fatalf("duplicate archive finding counted more than once per message: %+v", after.DetectionMessages)
    }
    if after.DetectionMessages["PHISHING_VISIBLE_LINK"]-before.DetectionMessages["PHISHING_VISIBLE_LINK"] != 20 {
        t.Fatalf("phishing detection event lost: %+v", after.DetectionMessages)
    }
    if _, ok := after.DetectionMessages["UNTRUSTED_DYNAMIC_SYMBOL"]; ok {
        t.Fatal("attacker-controlled metric label accepted")
    }
    after.DetectionMessages["PHISHING_VISIBLE_LINK"] = 0
    if RuntimeScanTelemetry().DetectionMessages["PHISHING_VISIBLE_LINK"] == 0 {
        t.Fatal("telemetry snapshot returned mutable map")
    }
}
