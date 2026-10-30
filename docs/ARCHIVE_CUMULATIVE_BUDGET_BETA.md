# Native beta: cumulative ZIP inspection resource limits

SpamGate's opt-in MIME attachment scanner now shares **one resource budget**
across the complete recursive ZIP tree, rather than resetting the allowance
for each nested ZIP. The defaults are 100 total ZIP members, 30 MiB of
cumulative declared expanded content, 8 MiB of actual inspected member data,
2 MiB per decompressed member and two nested ZIP levels. Exceeding the
entry budget emits `ARCHIVE_LIMIT`; exceeding declared expansion emits
`ARCHIVE_EXPANSION_RISK`. The scanner does not extract files to disk.

Regression tests exercise multiple ordinary nested archives, a combined
120-entry archive tree, and a nested aggregate-expansion case. These are
synthetic, deterministic fixtures, **not** measured real-world classifier
precision/recall or antivirus qualification. Archive scoring remains
subject to the existing optional inspection setting and signal policies.

This change does not modify the permanent foreground launcher
`/opt/spamgate/spamgate`, `spamgate-worker`, the persistent
`/opt/spamgate/data` directory, or Milter ports 38470/38472.
No production Postfix or Dovecot configuration is changed.
