# Public Suffix List snapshot notice

The bundled `internal/core/public_suffix_list.txt` is a filtered copy of the
Public Suffix List shipped as built-in data by the Debian-distributed Perl
`IO::Socket::SSL::PublicSuffix` module (file `/usr/share/perl5/IO/Socket/SSL/PublicSuffix.pm`,
August 2024 snapshot). Original list: https://publicsuffix.org/list/ .

Public Suffix List copyright holders/contributors are covered by **Mozilla
Public License 2.0**: https://mozilla.org/MPL/2.0/ . The snapshot removes
comments and blank lines and retains rule lines, including wildcard and
exception entries. Its source was distributed under that license and this
notice is retained in the SpamGate source tree.

**Operational warning:** the snapshot is not current as of October 2026.
For reliable organizational-domain DMARC with new delegated domains, download
a current publicsuffix.org list through your own approved administrative
workflow and configure `SPAMGATE_PUBLIC_SUFFIX_FILE` to the resulting local
file, then restart SpamGate. SpamGate does not fetch one without consent.
