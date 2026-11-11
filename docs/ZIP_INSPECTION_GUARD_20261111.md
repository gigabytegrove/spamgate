# ZIP attachment bounded inspection — 2026-11-11

Issue #5: This package provides a read-only, explicitly budgeted ZIP inspection primitive. It checks member counts, declared and streamed sizes, compression expansion ratio, unsafe member paths, nonregular members, and flags nested archive names. It does not extract files, follow paths, invoke external scanners, or alter mail disposition.

Usage: `archiveguard.Inspect(readerAt, zipByteLength, archiveguard.Limits{MaxFiles: 100, MaxMemberBytes: 16 << 20, MaxTotalBytes: 64 << 20, MaxRatio: 100})`. Callers must set all budgets and handle errors as an explicit unscanned state, not as a clean verdict. Nested archive members are counted, not recursively scanned. This primitive is not yet wired into the classifier pipeline; no new enforcement is claimed.

Verification: isolated package tests and vet executed locally on Go 1.23.2; GitHub exact-HEAD CI and production mail-host integration remain separate gates. Native launcher /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data and Milter 38470/38472 are unchanged.
