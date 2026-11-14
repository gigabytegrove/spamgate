# SMTP XFORWARD address-family integrity — 2026-11-13

## Change
XFORWARD ADDR parsing uses Go net/netip and refuses IPv4-mapped IPv6 addresses, whether bare, bracketed or IPv6-prefixed. These addresses formerly normalized to IPv4 under net.ParseIP.String, silently changing the apparent address family. Reject zone identifiers, ambiguous IPv4 leading-zero spellings, leading/trailing whitespace, malformed brackets and invalid addresses. Preserve canonical IPv4 and IPv6 spellings and supported Postfix bracket/IPv6: representations.

## Architecture
No changes to /opt/spamgate/spamgate, spamgate-worker, /opt/spamgate/data, or Milter ports 38470/38472. No production host configuration is changed.

## Evidence
The isolated parser package was run with Go 1.23.2: 25 table cases passed and go vet passed. The source and tests were then committed to main. This isolated test does not establish complete transport package build, end-to-end SMTP/Postfix compatibility, GitHub Actions success or real-host qualification.

## Outstanding acceptance
Validate trusted XFORWARD behavior against a disposable Postfix SMTP connection, including split commands, malformed identity rejection, AUTH/HELO attribution and transaction reset. Run full repository tests and exact-final-HEAD engineering and Postfix/Dovecot CI. GitHub issues #1-#9 remain open pending independent acceptance.
