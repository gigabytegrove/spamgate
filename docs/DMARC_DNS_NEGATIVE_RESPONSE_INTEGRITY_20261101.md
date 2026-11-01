# DMARC DNS negative-response integrity — 2026-11-01

## Production gate #3: parser hardening, not production qualification

The opt-in RFC 9989 `np=` DNS RCODE backend previously accepted a matching question and base RCODE=3 without validating the remaining DNS packet. A malformed authority/additional section or an EDNS OPT extended RCODE could therefore be mistaken for an actionable NXDOMAIN. Extended RCODE bits change the full response code, so a base RCODE of 3 is not sufficient evidence by itself.

This change validates every answer, authority, and additional resource-record boundary before trusting a nontruncated response. It rejects impossible record counts, truncated headers and RDATA, unaccounted trailing bytes, compression pointers into the DNS header, decompressed names over 255 octets, invalid/duplicate/misplaced OPT records, unsupported EDNS versions, nonzero extended RCODE bits, malformed EDNS options, and nonzero reserved DNS header Z bits. It retains the existing NXDOMAIN-with-answer ambiguity refusal, ID/question matching, bounded UDP/TCP fallback, and fail-closed DMARC temperror behavior.

The validator does not independently authenticate the DNS answer, verify DNSSEC denial-of-existence proofs, validate every RR type's RDATA semantics, or guarantee parity with system NSS/DoH/DoT resolution. An ordinary recursive resolver's NXDOMAIN is still only as trustworthy as that configured resolver. No network/mail server configuration or default behavior is changed: `SPAMGATE_DMARC_NP_DNS=system` remains an explicit opt-in.

## Test evidence

A standalone Go 1.23 isolated harness executed the section parser and RCODE decision path, including 13 malformed/contradictory packet cases, valid SOA/OPT negative replies, and a live loopback UDP extended-RCODE rejection. Local `go test`, `go test -race`, and `go vet` passed in the isolated harness. This is not equivalent to the full repository tests, GitHub CI, external DNS interoperability, or a real mail-host test. Exact-commit CI must be checked independently.

## Outstanding cumulative gates

GitHub issues #1–#9 remain open pending independent real Postfix/Dovecot disposition and holds, durable fault recovery, authentication interoperability, classifier precision, tenant policies, diagnostics, browser workflows, and native backup/update/rollback. Do not declare beta qualified from this parser change.

References: https://www.rfc-editor.org/rfc/rfc1035 and https://www.rfc-editor.org/rfc/rfc6891 and https://www.rfc-editor.org/rfc/rfc9989
