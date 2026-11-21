package main

import "fmt"

// deliveringLimitFailures checks verified, signed published records only.
// In-flight records are not treated as successful deliveries.
func deliveringLimitFailures(states map[string]int, maximum int) []string {
 if maximum < 0 || states["delivering"] <= maximum {
  return nil
 }
 return []string{fmt.Sprintf("delivering=%d exceeds max-delivering=%d", states["delivering"], maximum)}
}
