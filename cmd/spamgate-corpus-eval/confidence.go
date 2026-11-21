package main

import "math"

// wilsonUpper returns the one-sided upper endpoint of a Wilson score interval.
// A corpus with zero observed false positives still has a nonzero upper bound.
func wilsonUpper(positives, total int, z float64) float64 {
 if total <= 0 || positives < 0 || positives > total || math.IsNaN(z) || z < 0 { return math.NaN() }
 n := float64(total)
 p := float64(positives)/n
 z2 := z*z
 upper := (p+z2/(2*n)+z*math.Sqrt((p*(1-p)+z2/(4*n))/n))/(1+z2/n)
 if upper > 1 { return 1 }
 return upper
}
