# Native operations alert integrity — 2026-11-01

## Production gates #2 and #6: implementation, not acceptance

The durable operations monitor now records the delivery queue's `delivered` and `discard_pending` counts and due recovery/relay jobs, in addition to queued, delivering, dead-letter and unpublished originals. Queue backlog thresholds count both queued and delivering jobs. `SPAMGATE_MONITOR_DUE_THRESHOLD` defaults to 25 and accepts integers from 1 to 100000.

A failed or disabled outbox inventory cannot prove that a previously observed dead-letter, pending discard, unpublished original, backlog or due job has been repaired. Previously open `queue_*` alerts retain their last-seen evidence until an actual readable inventory establishes that the condition cleared. A failed enabled inventory raises `queue_unreadable`. An intentionally disabled outbox also does not silently clear prior evidence. The browser labels these states explicitly rather than implying healthy zeros.

The monitor's persisted JSON is now validated for duplicate, case-folded and escaped aliases, malformed Unicode escapes, invalid UTF-8 and trailing data before Go struct decoding. Ambiguous records remain untouched and cause a visible history-unavailable failure; no automatic repair or destructive reset occurs. Existing schema-1 JSON remains compatible, and added sample fields default to zero when reading older samples.

## Qualification evidence and limitations

New regressions exercise unreadable and disabled queue observations, restart persistence, healthy-inventory resolution, backlog across queued and delivering states, pending-discard capture from a real on-disk queue with an injected journal outage, private-data exclusion and duplicate-key corruption refusal. These are repository tests, not proof of power-loss or live Postfix/Dovecot delivery. Final exact-commit CI results must be inspected separately.

No production host, Postfix configuration, Dovecot configuration, Milter listener, systemd service or persistent mail directory is modified by this change. The native launcher and worker remain the sole supported Linux deployment path. All nine production gates remain open until independent end-to-end evidence satisfies their acceptance criteria.
