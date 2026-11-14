# Rspamd HTTP scanner disposition boundary — 2026-11-14

## Defect

The compatibility HTTP worker previously initialized every response action to `no action` and only mapped three known scanner decisions. An unknown or empty internal decision could therefore be reported to a connected MTA as successful acceptance. It also saved history before validating the final decision.

## Change

The worker now maps the core scanner's actual `accept`, `tag`, `quarantine`, and `reject` values explicitly. The legacy `no action` value remains an accepted compatibility alias. Empty, unexpected, and future unimplemented values return HTTP 503 instead of falsely reporting `no action`. Validation precedes history persistence. The client-facing error does not reveal an arbitrary internal action string.

## Evidence and limits

The new table-driven Go tests cover 11 supported and unsupported values. Isolated Go 1.23.2 test and vet execution passed; full repository compilation, race tests, and exact-final-HEAD GitHub Actions are separate checks. The live Postfix/Dovecot host was not modified. An HTTP 503 does not itself prove that every MTA configuration defers or retries; that behavior must be verified on a disposable and then authorized production mail host. This is a safety correction, not closure of issues #1–#9.

The native launcher, worker, persistent data location, and Postfix Milter ports remain unchanged.
