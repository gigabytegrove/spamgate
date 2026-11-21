# Classifier evidence filesystem preflight — 2026-11-21

## Scope

The paired JSONL comparator now opens baseline and candidate evidence through a shared preflight. Each pathname must identify a regular file, and the opened descriptor must still identify the file observed by the initial inspection. Baseline and candidate descriptors must refer to distinct filesystem objects; hardlink aliases and identical paths are rejected. Symlinks, directories, and missing files are rejected. Existing strict JSONL schema and classifier acceptance gates remain unchanged.

## Test coverage

`input_preflight_test.go` covers distinct regular files, identical paths, hardlink aliases, symlinks, directories, and missing files. Tests were committed but **not executed locally** because the engineering environment could not resolve github.com to clone the repository. The GitHub Actions result for the final commit must be inspected independently.

## Explicit limitations

This is not a content snapshot or cryptographic integrity guarantee. A concurrent writer can change the contents of an already-open file. A malicious pathname swap between Lstat and Open may also create a blocking-open risk on platforms without a nonblocking, descriptor-relative open. For high-trust qualification, place both inputs in a private, non-writable directory, use immutable captured corpora, and record SHA-256 hashes out of band. No live mail-host changes, Docker substitution, service restarts, or production classifier execution occurred.

## Production acceptance

This hardening is only a portion of issue #5. The comparator still consumes externally supplied scores rather than invoking the production classifier. Independently labeled representative corpora, production scoring, tenant runtime enforcement, and end-to-end mail-host evidence remain required. Do not close any production gate on this change alone.
