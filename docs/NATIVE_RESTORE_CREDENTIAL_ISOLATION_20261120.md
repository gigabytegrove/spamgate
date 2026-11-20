# Native restore credential isolation — 2026-11-20

Issue #8 security hardening. Cold restore now refuses any destination enclosing the signed manifest or authentication key, including symlinked directory aliases, exact-file destinations, and existing hardlink aliases. The check runs after the existing backup/active-data checks but before credentials are read or restore begins. Verify mode is unchanged.

## Evidence and limits

Standalone Go 1.23.2 tests exercised the helper's eight overlap/allow cases and missing/nonregular inputs with copies of the repository's path resolver. The full-repository CLI integration regression is committed but was not independently executed locally; the repository declares Go 1.27.4. GitHub Actions and disposable Postfix/Dovecot lab results must be inspected on the exact new commit. This preflight does not eliminate concurrent symlink or hardlink replacement (TOCTOU); production cold restore and rollback remain unqualified. No running mail service is touched.
