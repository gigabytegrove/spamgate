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
| GET | `/api/v1/signals` | Authenticated | List every built-in detector with default and effective weights |
| PUT | `/api/v1/signals/{symbol}` | Admin | JSON `score` (-100 to 100), `enabled` (boolean); future scans only |
| PUT | `/api/v1/settings` | Admin | Update policy thresholds and retention |
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
