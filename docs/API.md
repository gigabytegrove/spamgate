# SpamGate HTTP API — alpha v1

API root: `/api/v1`. All responses except export and static assets are JSON. Authenticated session requests must include `X-CSRF-Token` on POST, PUT or DELETE. Bearer-key clients must use `Authorization: Bearer sg_…` and an HTTPS connection. Scan body size is limited to 10 MiB. JSON management bodies are limited to 1 MiB.

| Method | Endpoint | Permission | Purpose |
| --- | --- | --- | --- |
| GET | `/healthz` | Public | Liveness/version (no credentials) |
| GET | `/api/v1/status` | Public | Whether first-run setup completed |
| POST | `/api/v1/setup` | One-time setup key | Creates admin: JSON `username`, `password`, `site_name`, `setup_key` |
| POST | `/api/v1/login` | Public | Sign in: JSON `username`, `password`; cookie issued |
| POST | `/api/v1/logout` | Authenticated session | Revokes session |
| GET | `/api/v1/me` | Authenticated | Current role and browser CSRF token |
| POST | `/api/v1/scan` | Admin session or scan/admin token | Scan raw RFC 5322 body; return full decision |
| GET | `/api/v1/messages?limit=100` | Admin or mapped mailbox | Newest history records, filtered by mailbox for users |
| GET | `/api/v1/messages/{id}` | Admin or receiving mailbox | Inspect full score and findings |
| POST | `/api/v1/messages/{id}/override` | Admin | JSON `action`, `reason` (5–500 chars) |
| POST | `/api/v1/messages/{id}/release` | Admin | Deliver held original to configured SMTP relay |
| DELETE | `/api/v1/messages/{id}/quarantine` | Admin | Permanently delete held original; journal a discarded verdict |
| GET | `/api/v1/statistics` | Admin or mailbox | Counts and score averages |
| GET | `/api/v1/export` | Admin | All retained history as newline-delimited JSON |
| GET | `/api/v1/config` | Admin or mailbox | Settings, rules and redacted accounts/tokens |
| GET | `/api/v1/bayes/stats` | Admin | Training sample counts, vocabulary size and readiness |
| POST | `/api/v1/bayes/train?label=spam` or `label=ham` | Admin | Raw RFC 5322 .eml file, max 10 MiB; persists a confirmed model sample |
| GET | `/api/v1/fuzzy/stats` | Admin | Active local near-duplicate fingerprints by class |
| GET | `/api/v1/fuzzy/entries` | Admin | Active fingerprint entries (ID, hashed signature, class, age) |
| POST | `/api/v1/fuzzy/train?label=spam` or `label=ham` | Admin | Raw `.eml` sample, 10 MiB max, at least 18 words; idempotent |
| DELETE | `/api/v1/fuzzy/entries/{id}` | Admin | Remove one trained reference by its fingerprint ID |
| GET | `/api/v1/neural/stats` | Admin | Count of confirmed historical messages used by local network |
| POST | `/api/v1/neural/train/{id}?label=spam` or `label=ham` | Admin | Train on existing history record's scoring symbols, once per ID |
| GET | `/api/v1/signals` | Authenticated | List every built-in detector with default and effective weights |
| PUT | `/api/v1/signals/{symbol}` | Admin | JSON `score` (-100 to 100), `enabled` (boolean); future scans only |
| PUT | `/api/v1/settings` | Admin | Update policy thresholds, retention and opt-in detection features |
| PUT | `/api/v1/recipient-policies` | Admin | Atomically replace per-mailbox threshold policies; see `EXTERNAL_INTELLIGENCE.md` |
| POST | `/api/v1/rules` | Admin or mailbox | Create scoring rule (mailbox users only sender policies) |
| DELETE | `/api/v1/rules/{id}` | Admin or rule owner | Remove rule |
| POST | `/api/v1/dns-lists` | Admin | Create DNSBL definition |
| DELETE | `/api/v1/dns-lists/{zone}` | Admin | Remove DNSBL definition |
| POST | `/api/v1/users` | Admin | Create restricted mailbox account |
| DELETE | `/api/v1/users/{name}` | Admin | Remove non-admin account |
| POST | `/api/v1/tokens` | Admin | Issue scan/admin API key; returned once |
| DELETE | `/api/v1/tokens/{name}` | Admin | Revoke API key |

## Scan request

`Content-Type: message/rfc822` and the complete unmodified RFC 5322 email in the body. Optional envelope metadata headers:

- `X-SpamGate-Sender`: original SMTP MAIL FROM address (not From header).
- `X-SpamGate-Recipients`: comma-delimited original RCPT TO addresses.
- `X-SpamGate-Client-IP`: originating SMTP client IP, supplied by a trusted integration. The raw HTTP client IP is **not** automatically treated as the origin of mail.

Response (`id`, timestamps, content and scores are illustrative):

```json
{
  "id": "a0123456789abcdef0123456789abcde",
  "timestamp": "2026-10-25T10:00:00Z",
  "sender": "sender@example.net",
  "recipients": ["inbox@example.com"],
  "subject": "Please verify your account",
  "connector": "http",
  "size": 512,
  "score": 2.5,
  "action": "accept",
  "findings": [
    {"symbol":"CONTENT_VERIFY_YOUR_ACCOUNT","source":"builtin/content","detail":"verify your account","score":2.5}
  ]
}
```

Actions: `accept`, `tag`, `quarantine`, `reject`. Header values and rules are administrator-provided. Custom systems **must interpret errors as an unavailable filtering decision**, not as accept. The HTTP scanner does not enqueue mail for delivery.

## Rule object

```json
{"name":"Fraud domain","kind":"sender_domain","value":"fraud.example","score":12,"action":"quarantine","enabled":true}
```

Supported `kind` values: `sender_email`, `sender_domain`, `recipient_email`, `client_ip`, `subject_contains`, `body_contains`, `url_domain`, `header_contains`. An empty `action` means threshold-only scoring. A force action can be `accept`, `tag`, `quarantine` or `reject`. `owner` is set by the server for mailbox accounts, not accepted from untrusted clients. For a per-user rule to affect a message, **every envelope recipient must match that mailbox**; mixed-recipient transactions are not implicitly rewritten.

## Error model

Non-2xx errors use `{"error":"human-readable explanation"}`. Common status codes: 400 bad data; 401 unauthenticated; 403 insufficient permission; 404 not found; 409 conflict; 413 too large; 429 login throttled; 502 upstream relay problem; 503 storage or setup not ready. These endpoints are subject to change while the API is alpha.

## Learning safety

Bayes, fuzzy and neural training all require administrator authorization and browser CSRF protection. They modify future scoring, not previous decisions. `fuzzy.json` fingerprints expire after 90 days; neural samples are keyed by historical message IDs and cannot currently be individually unlearned without resetting the model from backup. Neural signals deliberately exclude `NEURAL_*` and `FUZZY_*` symbols to prevent self-reinforcing training. All three datasets are considered sensitive; protect backups and use the Web UI to manage signals and fingerprints. Do not automatically train on delivery decisions.

## 0.4.0-alpha.1 operational APIs

All routes below are on the management listener (38470) and require a completed first-run setup. Browser writes require a valid session CSRF token; administration and all queue operations require an admin identity.

| Method | Route | Role | Description |
|---|---|---|---|
| GET | `/api/v1/history/search?q=&action=&sender=&recipient=&offset=0&limit=50&from=&to=` | admin or mailbox | Full retained-record search; RFC 3339 time boundaries; limits 1–500, offset 0–500000; mailbox identity isolation |
| PUT | `/api/v1/rules/{id}` | admin or rule owner | Replace matching rule, preserving server-assigned ID/owner; supports `priority`, `expires_at` RFC3339, and `enabled` |
| POST | `/api/v1/scan/simulate` | admin | Raw RFC 5322 message with the normal scan metadata headers, returns verdict without saving it |
| GET | `/api/v1/messages/{id}/preview` | admin | Truncated 4 KiB raw-text quarantine preview, JSON response; no HTML rendering |
| GET | `/api/v1/delivery-queue` | admin | Queue status and metadata only, **never raw email body** |
| POST | `/api/v1/delivery-queue/{id}/retry` | admin | Request immediate redelivery; may duplicate after uncertain remote SMTP completion |
| DELETE | `/api/v1/delivery-queue/{id}` | admin | Permanently discard. Requires `X-Confirm-Discard: discard queued original` header |
| GET | `/api/v1/integrations/diagnostics` | admin | Relay TCP reachability only; not a complete SMTP/TLS transaction test |
| GET | `/api/v1/metrics` | admin | Prometheus text exposition of retained history and queue gauges |

Do not publish management API or queue endpoints without HTTPS. Queue persistence requires a filesystem supporting atomic rename and file sync; on Windows directory sync cannot be guaranteed by this implementation. **Always keep backups** of the data directory while the service is quiescent; do not overwrite an active queue. Full DSN, idempotent downstream delivery and transactional multi-node replication are pending.
