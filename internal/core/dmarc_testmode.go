package core

// RFC 9989 section 4.7: t=y asks receivers to apply a policy one level
// weaker than the published p/sp/np. It never changes authentication
// pass/fail evidence and does not suppress independent local spam signals.
func effectiveDMARCPolicy(result DMARCResult) string {
	if !result.Testing {
		return result.Policy
	}
	switch result.Policy {
	case "reject":
		return "quarantine"
	case "quarantine":
		return "none"
	default:
		return "none"
	}
}
