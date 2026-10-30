# Bounded ZIP member inspection — October 30, 2026

This change advances issue #5 without changing the native launcher, Milter
ports, enforcement defaults, or the existing opt-in attachment-inspection flag.

* ZIP archives are inspected metadata-first (100 entries maximum per archive).
* A shared 8 MiB read budget limits all nested member decompression. Members
  over 2 MiB are never decompressed; nesting stops after two inner levels.
* Member content signatures detect MZ/ELF even when the filename is harmless.
  Nested ZIP content is inspected within the same shared budget.
* Path traversal, Windows drive paths, symlinks, risky filenames, declared
  expansion over 30 MiB, high compression ratios, encrypted entries and
  unreadable members produce explicit findings.
* Quoted-printable attachment decoding now reports oversize instead of
  silently truncating at 4 MiB.
* All positive attachment scores remain subject to the existing +10 scan cap.
  This is not antivirus or a complete malware sandbox. ClamAV remains separate.

Evidence limitations: deterministic fixtures are not an independently labelled
clean/spam corpus, and CI does not qualify real Postfix/Dovecot disposition or
production-host resource limits. Do not mark issue #5 complete on this basis.
