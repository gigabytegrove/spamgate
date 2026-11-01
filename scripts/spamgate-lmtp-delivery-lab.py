#!/usr/bin/env python3
"""Disposable-CI-only real Dovecot LMTP/Sieve/mailbox qualification.

Never run against production. Active direct LMTP delivery bypasses Postfix.
"""
import argparse
import json
import os
import re
import smtplib
import stat
import sys
import time
import uuid
from email.message import EmailMessage

from spamgate_bounded_command import CommandProbeError, capture_command

SOCKET = "/run/dovecot/lmtp"
RECIPIENT = "spamgatebeta@localhost"
USER = "spamgatebeta"
CONFIRM = "DISPOSABLE-DOVECOT-LMTP-DELIVERY"
MAX_WAIT = 12.0
CASES = (
    ("clean", None, None, "INBOX"),
    ("trusted_tag", "tag", True, "Junk"),
    ("trusted_quarantine", "quarantine", True, "Junk"),
    ("tag_without_id", "tag", False, "INBOX"),
    ("unrecognized_action", "reject", True, "INBOX"),
)
UID = re.compile(r"[a-fA-F0-9]{32}\s+[1-9][0-9]*\Z")


class LabFailure(Exception):
    """Fixed privacy-safe qualification failure."""


def assert_disposable(confirm, environ=None):
    env = os.environ if environ is None else environ
    if (confirm != CONFIRM or env.get("CI") != "true"
            or env.get("GITHUB_ACTIONS") != "true"
            or env.get("SPAMGATE_DISPOSABLE_LMTP_LAB") != "1"):
        raise LabFailure("disposable CI environment and explicit confirmation required")
    if os.name != "posix" or not os.path.exists(SOCKET):
        raise LabFailure("expected local Dovecot Unix socket unavailable")
    if not stat.S_ISSOCK(os.lstat(SOCKET).st_mode):
        raise LabFailure("expected Dovecot endpoint is not a Unix socket")


def message(case_id, action, include_id, run_id):
    if not re.fullmatch(r"[a-f0-9]{32}", run_id):
        raise LabFailure("invalid generated test identifier")
    msg = EmailMessage()
    msg["From"] = "lmtp-lab@localhost"
    msg["To"] = RECIPIENT
    msg["Subject"] = "Disposable LMTP delivery qualification " + case_id
    msg["Message-ID"] = "<" + run_id + "@spamgate-lmtp-lab.invalid>"
    if action is not None:
        msg["X-SpamGate-Action"] = action
    if include_id:
        msg["X-SpamGate-ID"] = run_id
    msg.set_content("Disposable isolated LMTP/Sieve delivery test; no real user mail.\n")
    return msg


def search_mailbox(folder, message_id, *, command=capture_command):
    if (folder not in ("INBOX", "Junk") or
            not re.fullmatch(r"<[a-f0-9]{32}@spamgate-lmtp-lab\.invalid>", message_id)):
        raise LabFailure("invalid mailbox evidence query")
    try:
        out, err, status = command(
            ["/usr/bin/doveadm", "search", "-u", USER, "mailbox", folder,
             "HEADER", "Message-ID", message_id], timeout=5, max_bytes=16384)
    except (CommandProbeError, OSError) as exc:
        raise LabFailure("bounded Dovecot mailbox search failed") from exc
    if status or err.strip():
        raise LabFailure("Dovecot mailbox search returned an error")
    try:
        lines = out.decode("ascii", "strict").splitlines()
    except UnicodeError as exc:
        raise LabFailure("Dovecot mailbox search returned invalid evidence") from exc
    if len(lines) > 2 or any(not UID.fullmatch(line.strip()) for line in lines):
        raise LabFailure("Dovecot mailbox search returned ambiguous evidence")
    return len(lines)


def counts(message_id, *, search=search_mailbox):
    return {folder: search(folder, message_id) for folder in ("INBOX", "Junk")}


def send_lmtp(msg, *, factory=smtplib.LMTP):
    try:
        with factory(SOCKET, timeout=8) as client:
            refused = client.sendmail("lmtp-lab@localhost", [RECIPIENT], msg.as_bytes())
            if refused:
                raise LabFailure("Dovecot LMTP refused the test recipient")
    except (OSError, smtplib.SMTPException) as exc:
        raise LabFailure("Dovecot LMTP delivery failed") from exc


def await_placement(message_id, expected, *, query=counts, clock=time.monotonic,
                    sleep=time.sleep, max_wait=MAX_WAIT):
    deadline = clock() + max_wait
    while True:
        last = query(message_id)
        if last["INBOX"] + last["Junk"] > 1:
            raise LabFailure("duplicate test delivery detected")
        if last[expected] == 1:
            final = query(message_id)
            if final != last:
                raise LabFailure("test delivery changed during verification")
            return final
        if last["INBOX"] + last["Junk"] == 1:
            raise LabFailure("Dovecot placed test message in the wrong mailbox")
        if clock() >= deadline:
            raise LabFailure("Dovecot mailbox placement not observed before deadline")
        sleep(0.25)


def execute(*, confirm, env=None, ids=None, send=send_lmtp, query=counts):
    assert_disposable(confirm, env)
    identifiers = ids if ids is not None else [uuid.uuid4().hex for _ in CASES]
    if len(identifiers) != len(CASES) or len(set(identifiers)) != len(CASES):
        raise LabFailure("invalid or duplicate test identifiers")
    results = []
    for (case_id, action, include_id, expected), run_id in zip(CASES, identifiers):
        msg = message(case_id, action, include_id, run_id)
        msg_id = str(msg["Message-ID"])
        if query(msg_id) != {"INBOX": 0, "Junk": 0}:
            raise LabFailure("test message identifier already exists")
        send(msg)
        placement = await_placement(msg_id, expected, query=query)
        results.append({"case": case_id, "expected": expected, "observed": expected,
                        "inbox": placement["INBOX"], "junk": placement["Junk"]})
    return {"schema": 1, "type": "disposable_dovecot_lmtp_delivery_evidence",
            "ok": True, "scope": "direct_dovecot_lmtp_sieve_mailbox_only",
            "cases": results, "verified_cases": len(results),
            "limitations": [
                "Direct LMTP submission bypasses Postfix and its Milter; forged header trust is not tested",
                "Only disposable local Dovecot LMTP, Sieve and doveadm mailbox visibility were exercised",
                "No production host, Postfix-to-LMTP routing, authentication or tenant isolation qualified",
            ]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm", default="")
    args = parser.parse_args(argv)
    try:
        result = execute(confirm=args.confirm)
    except (LabFailure, ValueError, OSError) as exc:
        reason = str(exc) if isinstance(exc, LabFailure) else "unexpected qualification error"
        result = {"schema": 1, "type": "disposable_dovecot_lmtp_delivery_evidence",
                  "ok": False, "error": reason, "scope": "direct_dovecot_lmtp_sieve_mailbox_only"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
