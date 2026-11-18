# Empty-directory portable identity preflight — 2026-11-18

Native backup creation now inventories all traversed source paths, including empty directories, before publication. Case-folded identities must be unique. The v1 file-only manifest cannot detect empty directory collisions after those directories have been omitted, so the source walk must reject them.

Regression tests cover two empty directories with names differing only by case, a case-colliding empty directory and regular file, and valid distinct directories. Rejection leaves the archive unpublished. This does not preserve empty directories during restore; a future versioned format and migration acceptance are still required. The offline lock remains mandatory, and this is not a filesystem snapshot.

Verification: source and regression fixtures committed; execution and production cold restore must be established independently. No Postfix, Dovecot, systemd, or running mail-server configuration was changed.
