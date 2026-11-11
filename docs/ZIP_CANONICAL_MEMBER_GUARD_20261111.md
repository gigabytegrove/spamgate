# ZIP archive inspection: canonical paths and supported methods

The native `internal/archiveguard` inspector now rejects noncanonical member paths (dot and parent segments, repeated separators, backslash aliases), malformed directory entries and compression methods other than ZIP Store (0) and Deflate (8). This prevents the scanner from treating an ambiguous member name or an uninspectable codec as successfully inspected.

These checks are **fail-closed at the inspection API boundary**, not a change to live mail disposition. The classifier is not yet wired to this package; callers must distinguish an inspection error from a clean verdict and must not silently turn errors into allow decisions.

Regression tests cover ambiguous paths, unsupported methods, and canonical directory/file acceptance. This is not nested-archive scanning, malware detection, production Postfix qualification or measured false-positive evidence. No mail-host configuration is modified.
