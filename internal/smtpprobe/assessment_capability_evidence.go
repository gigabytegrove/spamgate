package smtpprobe

// capabilityEvidenceFindings translates untrusted EHLO parser evidence into
// stable operator-facing findings. Raw peer strings are never reflected.
func capabilityEvidenceFindings(r Result, postTLS bool) []Finding {
	var warnings []string
	var sizeWarning string
	var sizeAdvertised, sizeKnown bool
	if postTLS {
		if !r.StartTLSVerified || r.PostTLSEHLOCode != 250 { return nil }
		warnings, sizeWarning = r.PostTLSEHLOWarnings, r.PostTLSSizeWarning
		sizeAdvertised, sizeKnown = r.PostTLSSizeAdvertised, r.PostTLSSizeLimitKnown
	} else {
		if r.EHLOCode != 250 { return nil }
		warnings, sizeWarning = r.EHLOWarnings, r.SizeWarning
		sizeAdvertised, sizeKnown = r.SizeAdvertised, r.SizeLimitKnown
	}
	out := []Finding{}
	if len(warnings) != 0 {
		out = append(out, Finding{
			Code: "SMTP_EHLO_CAPABILITY_ANOMALY", Severity: "warning",
			Message: "SMTP EHLO advertised malformed, duplicate, or inconsistent extensions; inspect the structured capability warnings",
		})
	}
	if sizeWarning != "" {
		out = append(out, Finding{
			Code: "SMTP_SIZE_LIMIT_UNTRUSTWORTHY", Severity: "warning",
			Message: "SMTP SIZE advertisement is malformed or ambiguous; do not use it as a trusted delivery-size limit",
		})
	} else if sizeAdvertised && !sizeKnown {
		out = append(out, Finding{
			Code: "SMTP_SIZE_LIMIT_UNSPECIFIED", Severity: "info",
			Message: "SMTP SIZE is advertised without a numeric maximum; this is not proof of unlimited message acceptance",
		})
	}
	return out
}
