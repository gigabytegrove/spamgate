# Read-only SMTP STARTTLS diagnostics (2026-11-11)

Run: `go run ./cmd/spamgate-smtp-probe -address 127.0.0.1:25 -tls-name mail.example.net -require-tls=true`

This opt-in diagnostic opens one connection, verifies the SMTP 220 banner, issues EHLO, inspects STARTTLS and AUTH advertisement, negotiates TLS 1.2+ with system CA and hostname verification, then repeats EHLO after TLS. No authentication credentials, MAIL FROM, RCPT TO, DATA, queue changes, or mail server reconfiguration. There is no insecure-skip-verify switch. A caller can explicitly use `-require-tls=false` to observe plaintext capabilities, never to authenticate or submit mail.

Exit 0 means successful inspection; exit 1 means SMTP/network/TLS failure; exit 2 means invalid invocation or output failure. JSON is emitted on protocol failures with partial diagnostic evidence. The probe is not a mail-delivery acceptance test.

Issues #3 and #6 remain open: SMTP AUTH exchange, SPF/DKIM/DMARC/ARC, Milter interoperability, real Postfix/Dovecot disposition, fault injection, alert history and production-host qualification are unverified. Synthetic local SMTP tests cover downgrade refusal, TLS refusal, bounded replies and invalid options.
