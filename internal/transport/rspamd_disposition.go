package transport

import "fmt"

// rspamdDisposition translates the scanner's final decision into the
// compatibility protocol. An unrecognized action must never be presented
// to an MTA as "no action": that would silently fail open.
func rspamdDisposition(action string) (string, error) {
 switch action {
 case "accept", "no action", "":
  // Empty is not a valid final scanner decision.
  if action == "" { return "", fmt.Errorf("empty scanner disposition") }
  return "no action", nil
 case "tag":
  return "add header", nil
 case "reject":
  return "reject", nil
 case "quarantine":
  return "quarantine", nil
 default:
  return "", fmt.Errorf("unsupported scanner disposition")
 }
}
