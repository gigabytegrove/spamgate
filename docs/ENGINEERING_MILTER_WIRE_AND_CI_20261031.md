# SpamGate native beta engineering — 2026-10-31, Milter wire safety and CI repair

Status: **not long-term beta-qualified**. Saturday morning America/New_York target was missed. This document records implementation and evidence; it is not a substitute for live mail-host qualification.

## Preserved deployment contract

- Native Linux. No Docker replacement.
- Permanent foreground launcher: `/opt/spamgate/spamgate`.
- Replaceable worker: `/opt/spamgate/spamgate-worker`.
- Persistent application state: `/opt/spamgate/data`.
- Management HTTP: `38470`; Postfix Milter: `127.0.0.1:38472`.
- Postfix `milter_default_action=accept` remains an operator-locked, fail-open configuration.
- No production service, Postfix configuration, binary, or data was modified by this engineering pass.

## Root-cause investigation

1. User's host source `eb9b7deda0fd71e3c93d59b91e2879efd4be8b0e`: full parallel `go test -race -count=1 ./...` failed launcher healthy-state timing, delivery concurrency completion, and Milter null sender timeout. Isolated race repetitions passed (3 launcher; 5 delivery; 5 Milter), and complete serialized `go test -race -p 1 -count=1 -timeout=15m ./...` passed all 13 packages. This supports resource contention/timing sensitivity but does not prove an absence of underlying race or throughput defects. Race instrumentation remains enabled. CI and the native asset builder now run serialized packages with bounded 15-minute package timeouts. The original parallel failure remains an open stress gate.
2. GitHub engineering qualification run [41208655759](https://github.com/gigabytegrove/spamgate/actions/runs/41208655759) on `81b52fb` failed **after its Go unit/race and UI steps passed**: `test_bounce_fails_even_if_sent` expected `bounced` but received `discard_or_error_transport`. Root cause: the Postfix evidence analyzer classified the `postfix/error` transport before inspecting its explicit `status=bounced`. Corrected precedence and added dedicated bounce and error-sent regressions. Both remain non-delivery states.
3. Milter response framing previously treated a short `io.Writer.Write` as success. The writer now continues until the complete frame is written or fails on error/no progress. Milter queue ID macro parsing now requires complete NUL-terminated name/value pairs and rejects duplicate/ambiguous queue identities. Header callbacks reject trailing unexpected bytes. Added fragmented writer, stalled/error writer, macro, header and poisoned-transaction recovery tests.

## Evidence levels

| Gate | Evidence | Status |
| --- | --- | --- |
| GitHub code pushed | Compare commit history after this document | Implemented |
| Go test on user's original host source | `eb9b7de`, 13/13 serialized race packages | Passed, **older source** |
| New Go Milter tests | Added to `internal/transport/milter_wire_hardening_test.go` | Must inspect final-commit CI |
| Postfix evidence Python tests | Added bounce/error precedence cases | Must inspect final-commit CI |
| Engineering CI on `81b52fb` | Run 41208655759 | **Failed**, known Python regression |
| Postfix/Dovecot isolated lab on `81b52fb` | Run 41208655820 | Passed for that earlier commit; not final-commit proof |
| Production Postfix/Dovecot accept/tag/hold/reject/IMAP/Junk | No new real-host observation | Unverified |
| Live launcher worker update/rollback, cold restore | No production execution | Unverified |
| Classifier real-world precision/recall and false-positive limits | No independently labeled corpus | Unverified |
| Browser UI real Chrome/Firefox/Edge click paths | No browser acceptance in this pass | Unverified |

## Safe operator qualification on updated source

The operator must review `git status --porcelain` and ensure no local modifications before fetching; the production binaries are separate and must remain untouched.

```bash
(
set -Eeuo pipefail
cd /opt/spamgate-source
test -z "$(git status --porcelain)"
git fetch origin main
git switch main
git merge --ff-only origin/main
export GOTOOLCHAIN=go1.27.3
echo "SOURCE $(git rev-parse HEAD)"
CGO_ENABLED=1 go test -race -p 1 -count=1 -timeout=15m ./...
CGO_ENABLED=1 go vet ./...
python3 scripts/test-spamgate-postfix-evidence.py -v
node --check internal/server/assets/app.js
node --test scripts/ui-regression.test.mjs
echo "Read-only source qualification completed; installed binaries unchanged."
)
```

## Open gates (cumulative)

- **#1 and #9:** independent live Postfix hold/release, Milter decisions, Sieve Junk/INBOX, Dovecot IMAP and exact queue-ID/recipient reconciliation, including duplicates and rollback.
- **#2:** crash/power-loss/disk-full spool state-transition and retry/DSN fault matrix.
- **#3:** third-party SPF/DKIM/DMARC/ARC and Milter interoperability vectors; actual protocol compliance.
- **#4:** per-tenant and per-recipient conflict handling, rule simulation and rollback.
- **#5:** representative clean/spam corpus, confidence bounds, MIME/archive attacks, false positives and poisoning resistance.
- **#6:** durable correlated diagnostics, retention, queue trends, alerts and injected-fault validation.
- **#7:** real browser UI workflows, keyboard and accessibility acceptance.
- **#8:** exact-commit native artifacts, installer/upgrade/rollback, cold restore and data-permission verification.

Do not close issues or declare beta ready until independent acceptance evidence exists.
