package main

import "math"

// compareWilsonUpper returns the two-sided 95% Wilson score interval's upper
// bound for a binomial proportion. The result is an estimate, not proof that
// the underlying false-positive rate is below this value.
func compareWilsonUpper(positives, total int) float64 {
 if total <= 0 || positives < 0 || positives > total { return math.NaN() }
 const z = 1.959963984540054
 n := float64(total)
 p := float64(positives)/n
 z2 := z*z
 center := p + z2/(2*n)
 margin := z*math.Sqrt(p*(1-p)/n+z2/(4*n*n))
 return math.Min(1,(center+margin)/(1+z2/n))
}
