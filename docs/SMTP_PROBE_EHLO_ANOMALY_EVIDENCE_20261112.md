# SMTP probe EHLO anomaly evidence — 2026-11-12

## Scope

The independent `internal/smtpprobe` read-only diagnostic now reports `ehlo_warnings` and `post_tls_ehlo_warnings` as deterministic JSON arrays. Only EHLO extension lines after the initial SMTP server identity line are examined. Findings include malformed extension keywords, empty extensions, duplicate extensions, unexpected arguments for parameterless capabilities, invalid/empty AUTH advertisements, and BINARYMIME without CHUNKING. The post-TLS field is populated only after a successful verified TLS handshake and successful post-TLS EHLO.

## Regression evidence

`capability_warnings_test.go` covers malformed and valid EHLO responses, dependency consistency, duplicate extensions, and stable warning ordering. `capability_warnings_socket_test.go` exercises the full read-only TCP probe with malformed AUTH and BINARYMIME and checks that no AUTH, MAIL, RCPT or DATA commands are sent. Source tests committed; exact-HEAD CI completion must be checked separately.

## Limits

Warnings describe advertisements, not demonstrated server behavior. These changes do not authenticate, submit mail, modify Postfix/Dovecot, prove durable delivery, or qualify a production mail host. All nine production gates remain open pending integration and real-host acceptance. The native foreground launcher, worker, data path and Milter ports remain unchanged.
