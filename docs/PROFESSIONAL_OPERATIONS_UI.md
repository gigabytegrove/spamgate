# SpamGate 0.6.0-alpha.2 — Operations UI refactor

This release changes the administrative Web UI only. It does not change mail scoring, quarantine enforcement, Postfix configuration, API contracts, or persisted data formats.

## Post-onboarding interface

Once `onboarding.completed` is true, the application no longer automatically redirects administrators to the setup wizard solely because the connector's `activated` flag is false. Instead, the Overview shows an actionable, non-blocking connection-status warning when needed. The administrator must still explicitly verify the mail path before considering the integration trusted.

The main header and primary mail navigation are preserved. The completed-installation secondary navigation prioritizes policy, rules, reputation, detectors and delivery. Setup, verification, message analysis, training, accounts and documentation remain accessible under the **System & tools** section. The product name remains SpamGate.

## Operations screens

- **Overview:** a selectable interval (24h / 7d / loaded history), scan counts by outcome, review backlog, recent scanned messages with score and action, recorded detection hits, and the active scoring thresholds. Counts are calculated from the last 1,000 fetched message records, *not* presented as a complete all-time accounting.
- **Review mail:** classification queue, reviewed versus pending counts, existing search and action filters, direct inspection, and existing detailed scoring and feedback actions. Message disposition remains separate from review status.
- **Policy and integration:** neutral, administrator-oriented labels; security warnings retained; wizard promoted only before setup is completed.
- **Documentation:** contextual references and release limitations are accessed deliberately instead of filling daily operations views.

No hidden production integration is inferred from an open Milter port. A scanner verdict is not evidence of final inbox delivery.

## Verification

- Go unit and server tests: `go test ./...`
- Race checks: `go test -race ./...`
- Go static analysis: `go vet ./...`
- JavaScript syntax: `node --check internal/server/assets/app.js`
- Isolated Chromium UI interaction test: post-onboarding nav, overview interval filter, review queue, manually re-opening wizard, viewport responsiveness and no JS exceptions, at 1440px and 390px.
- Final Linux binary: version and live HTTP `/healthz` plus embedded assets hash test.

The standalone binaries are development-test artifacts compiled using the available Go 1.23.2 toolchain; not approved for production rollout. The isolated Chromium test is not a full real-server browser test.
