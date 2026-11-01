# RFC 9989 np= Author Domain DNS RCODE backend — 2026-11-01

## Production gate #3: implementation, not qualification

The existing DMARC resolver contract correctly refused to infer NXDOMAIN from an empty TXT/A/MX lookup. However, the default Go net.Resolver did not implement the optional DMARCNameStatusResolver, leaving inherited np= policies with different sp=/p= dispositions inconclusive. This change adds an **opt-in**, standard-library-only DNS response-code transport for the default resolver; it does not change SMTP server settings, mail queues, persistent data, or the native foreground launcher.

Enable only after validating the host's DNS path: set SPAMGATE_DMARC_NP_DNS=system in the SpamGate service environment and restart during an approved maintenance window. **Unset by default.** Unknown values are disabled. When the caller injects a custom SPF resolver, that resolver must implement DMARCNameStatusResolver itself; the system transport is never mixed into a custom DNS view.

The transport reads up to 64 KiB of /etc/resolv.conf, uses at most three literal-IP nameservers, sends a single absolute A question for the exact Author Domain, validates transaction ID, standard DNS response, question name/type/class, and returns true only on NXDOMAIN (RCODE 3) with no answer records. NOERROR, including NODATA, returns false. SERVFAIL, REFUSED, malformed replies, mismatched questions, ambiguous NXDOMAIN-with-answer (potential CNAME target NXDOMAIN), timeouts and exhausted servers return errors; DMARC retains its existing non-actionable temperror behavior. Truncated UDP responses retry over TCP with a 4096-byte bound. Individual exchanges have a one-second deadline and inherit the existing five-second DMARC context.

### Evidence and limitations

Hermetic tests exercise local UDP and TCP DNS servers, NXDOMAIN/NODATA/SERVFAIL/REFUSED, truncated UDP-to-TCP fallback, malformed responses, compression pointer rejection, invalid configuration, cancellation, and opt-in/custom-resolver isolation. No external DNS or live mail host is contacted by the tests.

This is **not** independent DNSSEC validation, real-world recursive resolver interoperability, or evidence that the host's /etc/resolv.conf represents its complete NSS/DoH/DoT configuration. DNSSEC denial proofs, wildcard behavior, resolver split-horizon policy, systemd-resolved integration, IPv6 transport, retries and DNS rebinding must be qualified on a disposable and then authorized real mail host. Until then, leave opt-in disabled on production. Never promote beta based on this test suite alone.

Reference: https://www.rfc-editor.org/rfc/rfc9989.html
