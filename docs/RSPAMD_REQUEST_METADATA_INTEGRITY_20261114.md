# Rspamd HTTP request metadata integrity — 2026-11-14

## Implemented
The native Rspamd-compatible HTTP worker now rejects duplicate identity and control headers instead of silently using the first value returned by Go's Header.Get. Validated singleton headers: From, Helo, IP, Flags, Compression, Content-Encoding and Deliver-To. Repeated Rcpt fields remain supported, with a maximum of 100, a 512-byte per-field bound, and control-character rejection. Singleton length limits are From/Deliver-To 512, Helo 255, IP 64, Flags 256, Compression/Content-Encoding 64 bytes. The validation occurs before the scan and history save.

The original 10 MiB message-body limit, trusted-peer access policy, bearer authentication, and unsupported-flag/compression behavior remain in place. The change does not authorize direct Internet exposure or alter the running Postfix configuration.

## Evidence
The isolated Go 1.23.2 helper tests (16 table-driven cases) and isolated go vet were executed successfully before repository integration. Repository-wide compilation, regression suites, browser tests, Postfix/Dovecot laboratory tests, and exact-HEAD CI must be independently inspected; isolated helper execution does not establish those outcomes.

## Remaining qualification
Validate genuine Postfix/Rspamd request-header interoperability, multi-recipient envelope behavior, error mapping, and production-specific policy with real mail-host traces. Issues #1–#9 remain open; durable delivery, disposition, tenant-policy conflicts, classifier calibration, complete browser acceptance, backup/restore and native update/rollback are not certified by this change. The native launcher and worker, /opt/spamgate/data persistence, and ports 38470/38472 remain unchanged.
