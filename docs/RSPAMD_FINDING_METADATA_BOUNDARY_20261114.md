# Rspamd finding metadata boundary — 2026-11-14

The native HTTP worker now validates scanner finding symbols, details and source strings before emitting an MTA response or persisting history. Symbol identifiers use ASCII letters, digits and underscores, with no leading underscore. The limits are 256 bytes per symbol, 4096 bytes per detail, 256 bytes per source and 4096 findings per scan. Invalid UTF-8, ASCII control characters and non-finite aggregate scores fail closed with HTTP 503. A rejected response is not persisted by this handler.

This is a bounded response-integrity improvement, **not** proof of real Postfix/Dovecot disposition, durable accepted delivery, false-positive calibration, or production-host qualification. The existing native launcher, worker, persistent data path and Milter ports are unchanged.
