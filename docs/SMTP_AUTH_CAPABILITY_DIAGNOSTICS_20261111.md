# SMTP diagnostic qualification — 2026-11-11

Scope: native, read-only SMTP probe; issues #3 and #6. This is not mail-host certification.

## New observations

- `AUTH_NOT_ADVERTISED_AFTER_TLS`: initial EHLO advertises AUTH, verified STARTTLS completes, second EHLO succeeds (250), but the second EHLO has no AUTH mechanisms. This indicates a capability change worth investigation, not proof of authentication failure.
- `TLS_LEGACY_VERSION_NEGOTIATED`: TLS 1.2 was negotiated. Informational only: a single TLS 1.2 connection does not establish that the server lacks TLS 1.3.
- `AUTH_ADVERTISED_BEFORE_TLS` remains an observation, not proof that a server accepted unencrypted credentials.

## Verification boundary

Source and regression cases were committed on main. The regression suite covers capability presence/absence, unsuccessful second EHLO, unverified TLS, and TLS 1.2 versus TLS 1.3. No credentials or messages are submitted by the probe.

Local checkout/test execution was blocked by GitHub DNS resolution in the execution environment. Exact-HEAD push-triggered GitHub Actions completion and real production mail-host results were not verified at the time of this record. No production configuration was changed.

## Outstanding gates

Issues #1–#9 remain open pending real Postfix/Dovecot disposition, durable delivery, protocol and Milter interoperability, classifier corpus metrics, tenant isolation, complete UI/browser testing, operational diagnostics, backup/restore, and native update/rollback. Preserve the native launcher at /opt/spamgate/spamgate, worker spamgate-worker, persistent /opt/spamgate/data, and Milter ports 38470/38472.
