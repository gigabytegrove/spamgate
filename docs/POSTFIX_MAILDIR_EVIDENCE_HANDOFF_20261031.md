# Postfix to Maildir evidence handoff integrity — 2026-10-31

Issues #1, #6, #9. This pass fixes an evidence integrity gap, not the underlying mail-delivery engine.

## Defect

The Maildir evidence reader previously trusted the operator-provided
`complete_transport_correlation=true` and each entry's state string. A
fabricated or truncated transport report could omit a successful transport
event or queue removal while still being accepted as a successful Maildir
correlation if a matching Message-ID happened to exist.

## Correction

`scripts/spamgate_evidence_chain.py` independently checks all reported
successful cases against their queue lifecycle, recipient transport events,
single successful send count, absence of hold/discard/bounce, aggregate
counts, and chronology metadata. Contradictions refuse the entire handoff
before scanning Maildir. Existing synthetic tests now use complete evidence
objects; additional negative tests reject forged summary flags.

The Maildir report also includes `transport_chronology_validated`. This
is a *metadata flag*, not authenticated provenance. Untimestamped logs may
still establish file placement, but do not prove event chronology. Neither
tool establishes real Dovecot IMAP visibility or an independently authenticated
origin for operator-supplied reports.

## Verification

Run without modifying Postfix, Dovecot, systemd, or production data:

```bash
python3 scripts/test-spamgate-evidence-chain.py -v
python3 scripts/test-spamgate-maildir-evidence.py -v
python3 scripts/test-spamgate-postfix-evidence.py -v
```

The engineering workflow executes these regressions. Live host qualification
still requires separate actual Postfix queue and Dovecot mailbox evidence.
Do not close issues #1–#9 on these synthetic tests alone.

The permanent foreground launcher `/opt/spamgate/spamgate`, worker
`spamgate-worker`, persistent `/opt/spamgate/data`, HTTP 38470 and
Milter 38472 remain unchanged. No Docker replacement or production
mail-server deployment is part of this change.
