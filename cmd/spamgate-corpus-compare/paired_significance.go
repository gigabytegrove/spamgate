package main

import "math"

// pairedRegressionP computes the exact one-sided sign-test probability of
// observing at least regressions among discordant paired outcomes under p=0.5.
// Equal outcomes are intentionally excluded. No discordance means p=1.
// The calculation uses a stable log-domain sum to avoid 2^-n underflow.
func pairedRegressionP(regressions, fixes int) float64 {
 if regressions < 0 || fixes < 0 { return math.NaN() }
 n := regressions + fixes
 if n == 0 { return 1 }
 if regressions <= n/2 { // use the complementary lower tail
  return 1 - binomialHalfLower(n, regressions-1)
 }
 return binomialHalfLower(n, fixes)
}

func binomialHalfLower(n, k int) float64 {
 if k < 0 { return 0 }
 if k >= n { return 1 }
 // log(P(X=0)) = -n*ln(2), with recurrence for adjacent terms.
 logTerm := -float64(n)*math.Ln2
 maxLog := math.Inf(-1)
 sum := 0.0
 for i:=0; i<=k; i++ {
  if logTerm > maxLog {
   sum = sum*math.Exp(maxLog-logTerm)+1
   maxLog=logTerm
  } else {
   sum += math.Exp(logTerm-maxLog)
  }
  if i<k { logTerm += math.Log(float64(n-i))-math.Log(float64(i+1)) }
 }
 p:=math.Exp(maxLog)*sum
 if p>1 { return 1 }
 if p<0 { return 0 }
 return p
}
