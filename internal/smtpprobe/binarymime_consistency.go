package smtpprobe

// RFC 3030 requires CHUNKING when BINARYMIME is advertised. This
// diagnostic is read-only: no BDAT or mail submission is attempted.
func binaryMIMEConsistencyFindings(e ExtensionEvidence, prefix string) []Finding {
 if !e.BinaryMIME || e.CHUNKING { return nil }
 if extensionWarning(e.Warnings, "CHUNKING") {
  return []Finding{{Code:prefix+"_BINARYMIME_CHUNKING_AMBIGUOUS",Severity:"warning",Message:"BINARYMIME is advertised but CHUNKING evidence is malformed or duplicated; capability consistency cannot be established"}}
 }
 return []Finding{{Code:prefix+"_BINARYMIME_WITHOUT_CHUNKING",Severity:"warning",Message:"BINARYMIME is advertised without CHUNKING, contrary to RFC 3030; no BDAT transaction was attempted"}}
}
