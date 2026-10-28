# SpamGate v0.4.0-alpha.12 — task-first interface redesign

This release changes **the body of each SpamGate page** while preserving the approved SpamGate logo, masthead, primary and secondary navigation, routes, backend endpoints, and saved data format.

## Everyday workflows

- **Home:** A concise health explanation, clearly scoped counters, the latest accepted/flagged/rejected mail, an obvious review action, and direct access to policy. Advanced detection coverage is available only when expanded.
- **Review mail:** A chronological list of flagged decisions, plain-language explanations and a short three-step review guide. Scoring is explorable, but no longer dominates the review workflow.
- **Message details:** The administrator review actions are immediately after the key reasons. Complete score attribution and low-level transport information live behind separate disclosures. A review neither releases nor deletes an original.
- **Held messages:** Separate screens for SpamGate-saved SMTP originals and read-only Postfix holds. Never claim a Postfix hold was successfully released through the SpamGate API.
- **All messages:** Search recent or retained history using existing endpoints, display easy-to-read message rows, and open details for an exact decision.
- **Protection level:** Put tag, quarantine and reject thresholds first, then the Postfix hold/Junk choice. Reputation, greylisting, rate limiting and retention are grouped by task. Settings still use the existing `/api/v1/settings` PUT endpoint.
- **Rules:** List active rules first, then edit/create in a separate panel. Pause and delete controls stay available.
- **Reputation:** Show current configured providers separately from the form to add another, and explicitly disclose external DNS queries.
- **Scoring details:** Group built-in detectors by source with expand/collapse behavior; existing per-signal edit requests remain unchanged.
- **Teach the filter:** Provide two direct training forms, detailed local fuzzy inventory, and a separate experimental neural learning disclosure.
- **Delivery problems:** Clarify that an SMTP relay queue differs from Postfix's own queue; preserve confirmed retry and discard actions.
- **Mail server:** Show distinct states for listener, actual observed mail, and verification, with link to the exact-configuration wizard.
- **Help:** Task-oriented FAQ with routes to relevant features.

## Design behavior

- Neutral white/blue panels consistent with the supplied SpamGate logo; no green threat-console styling.
- No changed header/navigation or editable product name.
- Semantic sections, native details disclosures, screen-reader labels for searches, keyboard-operable links and buttons.
- Responsive desktop/tablet/phone layouts. Forms stay on their original IDs and field names to avoid backend regressions.
- New mail polling remains every four seconds; the active editor/dialog is not replaced while a user is typing or reviewing a message.
- Moving between sections clears the previous section's search/filter, preventing apparently empty pages caused by hidden stale queries.

## Operational limitations

This is a UI refactor, **not** a new detection release. It does not validate mail delivery, add Junk rules, make historical scoring more accurate, or address outstanding Milter/authentication parity gaps. Postfix holds remain read-only within the interface. Backend data and users are preserved when replacing only the standalone executable. Never apply a UI release directly to unrestricted incoming production email without a controlled smoke test.
