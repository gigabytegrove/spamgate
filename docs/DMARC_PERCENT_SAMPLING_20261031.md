# DMARC policy sampling and scoring — 2026-10-31

Issues #3 and #5: RFC 7489 pct sampling is now represented separately from DMARC authentication and used by the existing policy-based scoring. A failing DMARC authentication result remains fail even when sampled out. The published p= is retained; the effective scoring policy and sampling decision are recorded in the DMARC_FAIL finding, with an additional trace entry when sampled out.

Per RFC 7489 section 6.6.4, a sampled-out reject downgrades to quarantine, and sampled-out quarantine downgrades to none. Intermediate percentages use cryptographically unpredictable uniform draws. Entropy failure returns a scanner error. The parser rejects pct longer than three digits.

Scope boundary: SpamGate currently scores DMARC evidence (+6 reject, +4 quarantine, +0 none) but does not directly enforce publisher DMARC dispositions at the MTA. Other detector findings and explicit administrator signal overrides may still trigger a reject. Independent rescans may draw a different sample; persistent retry-stable sampling is outstanding.

Regression tests cover 0/100 and intermediate sampling boundaries, default and explicit percentages, invalid policy syntax, and end-to-end scanner scoring against synthetic DNS and isolated storage.

Remaining: PSD DMARC (RFC 9091), full third-party conformance, ARC trust, DMARC reporting, retry-stable sampling, direct policy enforcement, production Postfix/Dovecot qualification, and all other cumulative issues #1–#9. Do not claim beta or 1.0 qualification without end-to-end evidence.
