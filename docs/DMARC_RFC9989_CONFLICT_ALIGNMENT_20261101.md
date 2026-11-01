# RFC 9989 DMARC conflict and DKIM DNS outage safety — 2026-11-01

Issue #3, partial engineering qualification only.

RFC 9989 section 4.10 requires discarding **all** DMARC policy TXT records at one owner name when multiple version-matching records exist. The lookup now treats that name as having no usable policy, allowing the tree walk to continue. Previously it returned a terminal permerror. Non-DMARC TXT records are not counted.

A separate bug discarded DKIM alignment DNS errors through a self-assignment. When another signature was definitively unaligned, a published reject policy could become an actionable false-positive DMARC fail. The corrected loop preserves inconclusive DNS evidence; a different definitively aligned signature still passes.

Regression cases cover both DKIM signature orderings, unaligned SPF, aligned DKIM override, direct/intermediate duplicate records, unrelated TXT, missing policy, and parent DNS outages. Malformed **single** policy records still produce non-enforceable permerror. NXDOMAIN versus NODATA for the Author Domain, `np`, third-party interoperability, RFC 9990/9991 reporting, and real production mail-host qualification remain outstanding.

Native launcher `/opt/spamgate/spamgate`, worker `spamgate-worker`, persistent `/opt/spamgate/data`, and ports 38470/38472 are unchanged. No production service modification or deployment.

Normative source: https://www.rfc-editor.org/rfc/rfc9989.html sections 4.10–4.10.2.
