package main

import "fmt"

// queueLimitFailures checks only verified published states. Pending records
// are counted separately because they are not durably published deliveries.
// The caller must still reject incomplete audits and integrity findings.
func queueLimitFailures(states map[string]int, pending, maxQueued, maxDead, maxPending int) []string {
 var failures []string
 if maxQueued >= 0 && states["queued"] > maxQueued {
  failures = append(failures, fmt.Sprintf("queued=%d exceeds max-queued=%d", states["queued"], maxQueued))
 }
 if maxDead >= 0 && states["dead"] > maxDead {
  failures = append(failures, fmt.Sprintf("dead=%d exceeds max-dead=%d", states["dead"], maxDead))
 }
 if maxPending >= 0 && pending > maxPending {
  failures = append(failures, fmt.Sprintf("pending=%d exceeds max-pending=%d", pending, maxPending))
 }
 return failures
}
