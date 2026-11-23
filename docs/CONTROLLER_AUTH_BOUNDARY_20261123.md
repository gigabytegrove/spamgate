# Controller authentication boundary — 2026-11-23

Scope: Rspamd-compatible controller listener, not the management UI.

Before this change, Header.Get selected the first value for Authorization or Password, and a simultaneous Password header could be ignored. This allowed ambiguous HTTP authentication inputs to be silently interpreted as a single credential.

The controller now rejects missing, duplicate, simultaneous, malformed, and whitespace-padded credential headers before constant-time secret comparison. It accepts exactly one conventional Password header or one Authorization: Bearer token. CIDR checks, setup gating, and the existing read-only default remain in force.

Qualification: source committed; Go compilation, complete tests, browser acceptance, and production-host testing NOT EXECUTED without owner-controlled builder access. No live mail service changed. All issues #1–#9 remain open.
