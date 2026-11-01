#!/usr/bin/env python3
"""Disposable-CI-only evidence for Postfix -> Milter -> Dovecot LMTP.

Read-only evidence collector; the workflow alone changes the disposable MTA.
Never run on a production mail host.
"""
import argparse
import hashlib
import json
import os
import pathlib
import pwd
import re
import stat
import sys

from spamgate_bounded_command import CommandProbeError, capture_command

CONFIRM = "DISPOSABLE-POSTFIX-LMTP-QUALIFICATION"
SOCKET = "/var/spool/postfix/private/dovecot-lmtp"
USER = "spamgatebeta"
EXPECTED = {
    "mailbox_transport": "lmtp:unix:private/dovecot-lmtp",
    "mailbox_command": "/bin/false",
    "smtpd_milters": "inet:127.0.0.1:38472",
    "milter_default_action": "tempfail",
}
UID_LINE = re.compile(r"[a-fA-F0-9]{32} [1-9][0-9]*\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
MAX_EVIDENCE_BYTES = 65536


class QualificationFailure(Exception):
    """Privacy-safe, fixed diagnostic failure."""


def require_disposable(confirm, env=None):
    env = os.environ if env is None else env
    if (confirm != CONFIRM or os.name != "posix" or
            env.get("CI") != "true" or env.get("GITHUB_ACTIONS") != "true" or
            env.get("SPAMGATE_DISPOSABLE_POSTFIX_LMTP_LAB") != "1"):
        raise QualificationFailure("disposable CI and explicit confirmation required")


def run(args, command=capture_command):
    try:
        stdout, stderr, code = command(args, timeout=5, max_bytes=16384)
    except (CommandProbeError, OSError) as exc:
        raise QualificationFailure("bounded host evidence command failed") from exc
    if code or stderr.strip():
        raise QualificationFailure("host evidence command returned an error")
    try:
        return stdout.decode("ascii", "strict")
    except UnicodeError as exc:
        raise QualificationFailure("host evidence contains invalid text") from exc


def verify_route(*, command=capture_command, lstat=os.lstat, postfix_uid=None):
    for key, expected in EXPECTED.items():
        actual = run(["/usr/sbin/postconf", "-h", key], command=command).strip()
        if actual != expected:
            raise QualificationFailure("Postfix LMTP route or Milter safety preflight failed")
    try:
        metadata = lstat(SOCKET)
        uid = pwd.getpwnam("postfix").pw_uid if postfix_uid is None else postfix_uid
    except (OSError, KeyError) as exc:
        raise QualificationFailure("Dovecot Postfix LMTP socket unavailable") from exc
    if (not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != uid or
            stat.S_IMODE(metadata.st_mode) != 0o600):
        raise QualificationFailure("Dovecot Postfix LMTP socket identity or permissions unsafe")


def mailbox_fingerprints(folder, *, command=capture_command):
    if folder not in ("INBOX", "Junk"):
        raise QualificationFailure("invalid disposable mailbox")
    output = run(["/usr/bin/doveadm", "search", "-u", USER, "mailbox", folder, "ALL"],
                 command=command)
    lines = output.splitlines()
    if len(lines) > 256 or any(not UID_LINE.fullmatch(line.strip()) for line in lines):
        raise QualificationFailure("Dovecot mailbox inventory is ambiguous")
    if len(lines) != len(set(lines)):
        raise QualificationFailure("Dovecot mailbox inventory contains duplicates")
    return sorted(hashlib.sha256((folder + "\0" + line).encode("ascii")).hexdigest()
                  for line in lines)


def snapshot(*, command=capture_command, lstat=os.lstat, postfix_uid=None):
    verify_route(command=command, lstat=lstat, postfix_uid=postfix_uid)
    return {
        "schema": 1,
        "scope": "disposable_postfix_milter_dovecot_lmtp",
        "route_verified": True,
        "mailboxes": {
            folder: mailbox_fingerprints(folder, command=command)
            for folder in ("INBOX", "Junk")
        },
    }


def verify_delta(before, after):
    for value in (before, after):
        if not isinstance(value, dict) or value.get("schema") != 1 or (
                value.get("scope") != "disposable_postfix_milter_dovecot_lmtp") or (
                value.get("route_verified") is not True):
            raise QualificationFailure("invalid Postfix LMTP evidence schema")
        boxes = value.get("mailboxes")
        if not isinstance(boxes, dict) or set(boxes) != {"INBOX", "Junk"}:
            raise QualificationFailure("invalid Postfix LMTP mailbox evidence")
        for values in boxes.values():
            if (not isinstance(values, list) or len(values) > 256 or
                    any(not isinstance(v, str) or not DIGEST.fullmatch(v) for v in values) or
                    len(values) != len(set(values))):
                raise QualificationFailure("ambiguous Postfix LMTP mailbox fingerprints")
    changes = {}
    for folder, expected in (("INBOX", 4), ("Junk", 1)):
        previous = set(before["mailboxes"][folder])
        current = set(after["mailboxes"][folder])
        if not previous.issubset(current):
            raise QualificationFailure("existing Dovecot mailbox messages disappeared")
        added = len(current - previous)
        if added != expected:
            raise QualificationFailure("Postfix LMTP mailbox delivery count mismatch")
        changes[folder] = added
    return {
        "schema": 1,
        "type": "disposable_postfix_milter_lmtp_evidence",
        "ok": True,
        "scope": "real_postfix_milter_dovecot_lmtp_disposable_vm_only",
        "route_verified": True,
        "new_inbox": changes["INBOX"],
        "new_junk": changes["Junk"],
        "limitations": [
            "No production mail host or ISPConfig configuration was tested",
            "Go integration verifies SMTP accept, reject, tempfail, hold/release, tag and forgery behavior",
            "Mailbox fingerprints prove additions and preservation, not durable crash recovery",
        ],
    }


def read_snapshot(path):
    try:
        if pathlib.Path(path).is_symlink():
            raise QualificationFailure("evidence symlink refused")
        with open(path, "rb") as handle:
            raw = handle.read(MAX_EVIDENCE_BYTES + 1)
        if len(raw) > MAX_EVIDENCE_BYTES:
            raise QualificationFailure("evidence file too large")
        return json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise QualificationFailure("cannot parse bounded Postfix LMTP evidence") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--snapshot", action="store_true")
    mode.add_argument("--verify", nargs=2, metavar=("BEFORE", "AFTER"))
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    try:
        require_disposable(args.confirm)
        result = snapshot() if args.snapshot else verify_delta(
            read_snapshot(args.verify[0]), read_snapshot(args.verify[1]))
    except QualificationFailure as exc:
        result = {"schema": 1, "type": "disposable_postfix_milter_lmtp_evidence",
                  "ok": False, "error": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok", args.snapshot) and "error" not in result else 1


if __name__ == "__main__":
    sys.exit(main())
