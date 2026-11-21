package main

import (
 "fmt"

 "github.com/gigabytegrove/spamgate/internal/spoolaudit"
)

// deliveryAgeFailures evaluates verified published records only. Age is
// measured from original creation, including time spent in retry cycles.
func deliveryAgeFailures(report spoolaudit.Report, maxQueued, maxDelivering, maxDead int64) []string {
 var failures []string
 if maxQueued >= 0 && report.OldestQueuedSeconds > maxQueued {
  failures = append(failures, fmt.Sprintf("queued_age_seconds=%d exceeds max-queued-age-seconds=%d", report.OldestQueuedSeconds, maxQueued))
 }
 if maxDelivering >= 0 && report.OldestDeliveringSeconds > maxDelivering {
  failures = append(failures, fmt.Sprintf("delivering_age_seconds=%d exceeds max-delivering-age-seconds=%d", report.OldestDeliveringSeconds, maxDelivering))
 }
 if maxDead >= 0 && report.OldestDeadSeconds > maxDead {
  failures = append(failures, fmt.Sprintf("dead_age_seconds=%d exceeds max-dead-age-seconds=%d", report.OldestDeadSeconds, maxDead))
 }
 return failures
}
