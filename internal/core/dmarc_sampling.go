package core

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// RFC 7489 section 6.6.4: a sampled-out reject downgrades to quarantine,
// and a sampled-out quarantine downgrades to none. The DMARC authentication
// result remains fail. draw must be a uniform integer in [0, 99].
func dmarcPolicyAtSample(policy string, percent, draw int) (string, bool) {
	if draw < percent {
		return policy, true
	}
	switch policy {
	case "reject":
		return "quarantine", false
	case "quarantine":
		return "none", false
	default:
		return "none", false
	}
}

// Random draws are unpredictable to senders. Failure to obtain entropy
// is an explicit scanner error, never a silent policy bypass.
func chooseDMARCPolicy(result DMARCResult) (string, bool, error) {
	if result.Result != "fail" {
		return result.Policy, true, nil
	}
	if result.Percent < 0 || result.Percent > 100 {
		return "", false, fmt.Errorf("invalid DMARC percentage %d", result.Percent)
	}
	if result.Percent == 0 {
		policy, selected := dmarcPolicyAtSample(result.Policy, 0, 0)
		return policy, selected, nil
	}
	if result.Percent == 100 {
		return result.Policy, true, nil
	}
	draw, err := rand.Int(rand.Reader, big.NewInt(100))
	if err != nil {
		return "", false, err
	}
	policy, selected := dmarcPolicyAtSample(result.Policy, result.Percent, int(draw.Int64()))
	return policy, selected, nil
}
