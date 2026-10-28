# SpamGate alpha.10 — Navigation and operational diagnostics

This update removes the former "workspaces" sidebar. The regular document is
now the only scrollable page region. The seven primary destinations are
Overview, Review mail, Held mail, All messages, Protection, Diagnostics and
Settings. Secondary controls are shown in a short related-tools bar only for
the corresponding area. Message inspector panels remain deliberately scrollable
when opened as a modal.

## What Diagnostics really checks

Authenticated administrators visit `/diagnostics` or select **Diagnostics**.
On entry, and when **Run all checks** is pressed, the browser requests these
existing backend endpoints, each independently so one failure does not hide
successful observations:

| Source | Evidence used | Limitation |
| --- | --- | --- |
| `/api/v1/runtime` | Configured mail and controller listeners, outbound relay configured | Configuration is not proof of socket acceptance or mail delivery |
| `/api/v1/setup/readiness` | Setup state, expected connector, Postfix attachment inspection, observed mail and verified challenge | Observed scans alone never certify final mailbox delivery |
| `/api/v1/host` | Read-only local MTA inspection | Host inspection is not available for remote Postfix installations |
| `/api/v1/integrations/diagnostics` | TCP probe of configured SMTP relay, checked time and failure detail | TCP connectivity does not verify SMTP transaction, STARTTLS or credentials |
| `/api/v1/delivery-queue` | Durable queue state and failed-job count, when enabled | Postfix hold queue is separate; queue actions require privileged operation |
| `/api/v1/metrics` | Scanner total, error total and per-connector counters | Runtime counters reset at every restart, not durable service-level metrics |
| `/api/v1/statistics` | Retained decision history and version | Retention limits apply; not an exhaustive lifetime counter |

All these endpoints use existing administrator authentication and do not make
mail-routing changes. A failure is displayed with the failed source, not
silently treated as healthy. Raw response data is never rendered as HTML.

The troubleshooting guide contains only **read-only** commands for Postfix
configuration inspection, listener inspection, hold-queue listing, and mail
service logs. These commands are examples to execute on the applicable Linux
mail server, not a remote-execution feature of SpamGate.

## Why this is not end-to-end delivery certification

- A SpamGate verdict is a requested filtering action, not an MTA outcome.
- `sent` in a Postfix log means next-hop acceptance, not necessarily mailbox delivery.
- SpamGate's persisted SMTP original, Postfix's hold queue and its durable
  delivery retry queue are distinct. Release one only after identifying the
  original's location and current state.
- Only the saved setup challenge and administrator confirmation mark a verified
  mail-flow test. This is not continuous validation of a live Postfix service.

## Troubleshooting

Open **Diagnostics → System checks** and click **Run all checks**. Check the
actual listener mode and Postfix Milter settings. **Mail connections** has the
setup wizard and relay test. **Delivery queue** shows retry state, while **All
messages** opens the recorded score, authentication evidence, headers and
per-message Postfix evidence when available. For upgrades, **Settings →
Software updates** checks actual published releases; a Git tag by itself is
not a usable updater release.

## Tests

Run `go test ./...`, `go test -race ./...`, `go vet ./...` and
`node --test scripts/ui-regression.test.mjs`. The browser screenshot/keyboard
review and live Postfix-Dovecot integration qualification still require a real
interactive deployment.
