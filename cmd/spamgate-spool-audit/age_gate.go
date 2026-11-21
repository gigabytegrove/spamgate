package main

import (
 "fmt"

 "github.com/gigabytegrove/spamgate/internal/spoolaudit"
)

// deliveryAgeFailures evaluates verified published records only. Age is
// measured from original creation, including time spent in retry cycles.
func deliveryAgeFailures(report spoolaudit.Report, maxQueued, maxDelivering int64) []string {
 var failures []string
 if maxQueued >= 0 && report.OldestQueuedSeconds > maxQueued {
  failures = append(failures, fmt.Sprintf("queued_age_seconds=%d exceeds max-queued-age-seconds=%d", report.OldestQueuedSeconds, maxQueued))
 }
 if maxDelivering >= 0 && report.OldestDeliveringSeconds > maxDelivering {
  failures = append(failures, fmt.Sprintf("delivering_age_seconds=%d exceeds max-delivering-age-seconds=%d", report.OldestDeliveringSeconds, maxDelivering))
 }
 return failures
}
