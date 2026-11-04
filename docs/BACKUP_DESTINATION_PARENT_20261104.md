# Backup destination parent revalidation — 2026-11-04

## Defect
The offline backup creator resolves the destination parent before writing its temporary archive. A renamed parent or swapped symlink after that check could redirect the final hard-link publication to a different directory, including the source data tree. The original lexical and resolved-prefix checks only covered the initial state.

## Correction
Record the destination parent pathname inode identity and resolved location before writing the archive. After archive readback and immediately before hard-link publication, revalidate both. Reject replacement directories and symlink redirection without publishing the archive. The tests exercise stable parents, same-path replacement, and a symlink retargeted toward the data directory.

## Limitations
This is a best-effort race-window reduction, not a race-free guarantee: a hostile process can still change a parent between the final check and `os.Link`. A complete defense requires descriptor-relative publication with Linux `linkat` and controlled parent-directory handles. Backups remain offline and require the worker lock. This change does not qualify real production backup/restore, crash durability, or native rollback. No mail-host configuration was changed.
