#!/usr/bin/env python3
"""Bounded, opt-in native SMTP corpus qualification and evidence reconciliation.

Never changes Postfix, Dovecot, SpamGate, or installed data. The manifest's
ham/spam labels must be independently adjudicated; SMTP 250 is not delivery.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import smtplib
import ssl
import sys
import time
import uuid
from email import policy
from email.parser import BytesParser

MAX_CASES = 1000
MAX_BYTES = 128 * 1024
COHORTS = {"direct", "forwarded", "attachment", "internationalized", "bulk", "other"}
ACTIONS = {"accept", "tag", "quarantine", "reject", "soft_reject"}
CASE_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\\Z")
RUN_ID = re.compile(r"[0-9a-f]{32}\\Z")


def reject_duplicate_json_keys(pairs):
    """Reject even escaped aliases and nested duplicate keys before coercion."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def reject_nonfinite_json(value):
    raise ValueError("non-finite JSON number is not permitted")



def load_jsonl(path, limit):
    records = []
    with open(path, "rb") as handle:
        for number, raw in enumerate(handle, 1):
            # Bound physical lines as well as nonempty records. Otherwise an
            # unbounded blank-line file can monopolize an offline operator run.
            if number > 4 * limit + 128:
                raise ValueError(f"{path}: exceeds physical line limit")
            if len(raw) > 65536:
                raise ValueError(f"{path}: line {number} exceeds 64 KiB")
            if not raw.strip():
                continue
            if len(records) >= limit:
                raise ValueError(f"{path}: exceeds {limit} records")
            try:
                record = json.loads(
                    raw,
                    object_pairs_hook=reject_duplicate_json_keys,
                    parse_constant=reject_nonfinite_json,
                )
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"{path}: line {number} is invalid JSON") from exc
            if not isinstance(record, dict):
                raise ValueError(f"{path}: line {number} is not an object")
            records.append(record)
    return records


def load_manifest(path):
    root = pathlib.Path(path).resolve().parent
    cases = load_jsonl(path, MAX_CASES)
    if not cases:
        raise ValueError("empty corpus manifest")
    ids, digests = set(), set()
    result = []
    for case in cases:
        if set(case) != {"case_id", "label", "cohort", "file"}:
            raise ValueError("manifest requires only case_id, label, cohort, file")
        cid = case["case_id"]
        if not isinstance(cid, str) or not CASE_ID.fullmatch(cid) or cid in ids:
            raise ValueError("invalid or duplicate case_id")
        if not isinstance(case["label"], str) or not isinstance(case["cohort"], str) or case["label"] not in ("ham", "spam") or case["cohort"] not in COHORTS:
            raise ValueError(f"{cid}: invalid independently assigned label or cohort")
        name = case["file"]
        if not isinstance(name, str) or not name.endswith(".eml"):
            raise ValueError(f"{cid}: expected .eml fixture")
        candidate = pathlib.Path(name)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError(f"{cid}: fixture must be relative and contained")
        candidate = root / candidate
        if candidate.is_symlink() or any(part.is_symlink() for part in list(candidate.parents) if part != root and root in part.parents):
            raise ValueError(f"{cid}: symlinked fixture path refused")
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(root) or not resolved.is_file():
            raise ValueError(f"{cid}: fixture escapes corpus root or is not regular")
        if resolved.stat().st_size > MAX_BYTES:
            raise ValueError(f"{cid}: fixture exceeds {MAX_BYTES} bytes")
        with resolved.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError(f"{cid}: fixture changed or exceeds limit")
        digest = hashlib.sha256(data).hexdigest()
        if digest in digests:
            raise ValueError(f"{cid}: duplicate message bytes; corpus sample inflation refused")
        ids.add(cid)
        digests.add(digest)
        result.append({"case_id": cid, "label": case["label"], "cohort": case["cohort"],
                       "file": str(resolved), "id": digest})
    return result


def make_message(case, recipient, run_id):
    with pathlib.Path(case["file"]).open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or hashlib.sha256(data).hexdigest() != case["id"]:
        raise ValueError("fixture changed after manifest validation")
    msg = BytesParser(policy=policy.default).parsebytes(data)
    if msg.defects:
        raise ValueError(f"{case['case_id']}: malformed RFC 5322 fixture")
    for key in list(msg.keys()):
        if key.lower() in {"to", "cc", "bcc", "return-path", "message-id", "dkim-signature", "authentication-results", "x-spamgate-probe-id"} or key.lower().startswith("resent-"):
            del msg[key]
    msg["To"] = recipient
    msg["X-SpamGate-Probe-ID"] = run_id
    msg["Message-ID"] = f"<{run_id}@spamgate-qualification.invalid>"
    if len(msg.as_bytes(policy=policy.SMTP)) > MAX_BYTES:
        raise ValueError("rewritten fixture exceeds message limit")
    return msg


def exclusive_output(path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        parent = os.path.dirname(os.path.abspath(path))
        directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        os.close(fd)
        os.unlink(path)
        raise
    return os.fdopen(fd, "w", encoding="utf-8")


def record(handle, row):
    handle.write(json.dumps(row, sort_keys=True) + "\n")
    handle.flush()
    os.fsync(handle.fileno())


def address(value):
    if not isinstance(value, str) or any(ch in value for ch in "\r\n\x00<> \t") or value.count("@") != 1:
        raise argparse.ArgumentTypeError("one plain email address required")
    local, domain = value.rsplit("@", 1)
    if not local or not domain:
        raise argparse.ArgumentTypeError("invalid email address")
    return value


def run_send(args, cases):
    if args.recipient != args.confirm_recipient:
        raise ValueError("recipient confirmation must exactly match")
    try:
        ip = ipaddress.ip_address(args.host)
    except ValueError as exc:
        raise ValueError("SMTP host must be an IP literal to prevent DNS rebinding") from exc
    if not ip.is_loopback and not args.allow_remote:
        raise ValueError("non-loopback SMTP target requires --allow-remote")
    if not 1 <= args.port <= 65535 or not 0 < args.timeout <= 120 or not 0.25 <= args.interval <= 60:
        raise ValueError("invalid port, timeout or interval")
    prepared = []
    for case in cases:
        run_id = uuid.uuid4().hex
        prepared.append((case, run_id, make_message(case, args.recipient, run_id)))
    with exclusive_output(args.output) as output:
        # A durable plan prevents a partial accepted prefix from being
        # mistaken for a complete qualification corpus after a crash.
        record(output, {"event": "plan", "cases": len(prepared)})
        try:
            with smtplib.SMTP(args.host, args.port, timeout=args.timeout, local_hostname="spamgate-qualification.invalid") as smtp:
                smtp.ehlo_or_helo_if_needed()
                if args.starttls:
                    smtp.starttls(context=ssl.create_default_context())
                    smtp.ehlo()
                for index, (case, run_id, msg) in enumerate(prepared):
                    base = {"case_id": case["case_id"], "id": case["id"],
                            "label": case["label"], "cohort": case["cohort"], "run_id": run_id}
                    record(output, {**base, "event": "attempted"})
                    try:
                        refused = smtp.send_message(msg, from_addr=args.sender, to_addrs=[args.recipient])
                        if refused:
                            record(output, {**base, "event": "failed", "error": "recipient_refused"})
                            return 3
                        record(output, {**base, "event": "smtp_accepted"})
                    except (smtplib.SMTPException, OSError) as exc:
                        record(output, {**base, "event": "failed", "error": type(exc).__name__})
                        return 3
                    if index + 1 < len(prepared):
                        time.sleep(args.interval)
        except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
            print(f"SMTP session failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 3
    return 0


def reconcile(args):
    events = load_jsonl(args.report, 2 * MAX_CASES + 1)
    if (not events or set(events[0]) != {"event", "cases"}
            or events[0]["event"] != "plan"
            or type(events[0]["cases"]) is not int
            or not 1 <= events[0]["cases"] <= MAX_CASES):
        raise ValueError("missing or invalid durable batch plan")
    planned_count = events[0]["cases"]
    events = events[1:]
    observed = load_jsonl(args.observations, MAX_CASES)

    attempts, accepted, failed = {}, set(), set()
    run_ids, digests = set(), set()
    pending = None
    required = {"case_id", "id", "label", "cohort", "run_id", "event"}
    for row in events:
        if not isinstance(row, dict):
            raise ValueError("report event must be an object")
        event = row.get("event")
        expected = required | ({"error"} if event == "failed" else set())
        if event not in {"attempted", "smtp_accepted", "failed"} or set(row) != expected:
            raise ValueError("unexpected or incomplete report event fields")
        cid, run_id, digest = row["case_id"], row["run_id"], row["id"]
        if (not isinstance(cid, str) or not CASE_ID.fullmatch(cid)
                or not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id)
                or not isinstance(digest, str) or not DIGEST.fullmatch(digest)
                or type(row["label"]) is not str or row["label"] not in ("ham", "spam")
                or type(row["cohort"]) is not str or row["cohort"] not in COHORTS):
            raise ValueError("invalid report identity, label or cohort")
        if event == "failed" and (not isinstance(row["error"], str)
                                  or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,79}", row["error"])):
            raise ValueError("invalid report failure category")
        if event == "attempted":
            if pending is not None:
                raise ValueError("attempt lacks its durable terminal outcome")
            if cid in attempts or run_id in run_ids or digest in digests:
                raise ValueError("duplicate case, run ID or message digest")
            attempts[cid] = row
            run_ids.add(run_id)
            digests.add(digest)
            pending = cid
        else:
            if pending != cid or cid not in attempts:
                raise ValueError("terminal event does not follow its attempt")
            if any(row[key] != attempts[cid][key]
                   for key in ("case_id", "id", "label", "cohort", "run_id")):
                raise ValueError("terminal event contradicts its attempt")
            (accepted if event == "smtp_accepted" else failed).add(cid)
            pending = None
    if pending is not None or len(attempts) != planned_count or len(accepted) != planned_count or failed:
        raise ValueError("incomplete or failed SMTP intake: no classifier qualification")

    observations = {}
    for row in observed:
        if (not isinstance(row, dict) or set(row) != {"run_id", "action"}
                or not isinstance(row["run_id"], str) or not RUN_ID.fullmatch(row["run_id"])
                or not isinstance(row["action"], str) or row["action"] not in ACTIONS):
            raise ValueError("observation requires a valid run_id and actual action")
        if row["run_id"] in observations:
            raise ValueError("duplicate observed run ID")
        observations[row["run_id"]] = row["action"]
    if set(observations) != run_ids:
        raise ValueError("missing or unrelated observed actions; no implicit accept verdicts")

    rows = []
    for case in attempts.values():
        rows.append({"id": case["id"], "label": case["label"],
                     "cohort": case["cohort"], "action": observations[case["run_id"]]})
    # Publish only complete label sets; never overwrite prior evidence.
    # An interrupted evaluation must not leave a partial qualifying corpus.
    target = pathlib.Path(args.labels_out)
    temporary = target.with_name(f".{target.name}.pending-{uuid.uuid4().hex}")
    try:
        with exclusive_output(temporary) as output:
            for row in rows:
                record(output, row)
        os.link(temporary, target)
        temporary.unlink()
        directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    return len(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    plan = sub.add_parser("plan", help="validate corpus and print content-free summary; never send")
    plan.add_argument("--manifest", required=True)
    send = sub.add_parser("send", help="explicitly transmit to one confirmed test mailbox")
    send.add_argument("--manifest", required=True)
    send.add_argument("--recipient", required=True, type=address)
    send.add_argument("--confirm-recipient", required=True, type=address)
    send.add_argument("--sender", required=True, type=address)
    send.add_argument("--host", default="127.0.0.1")
    send.add_argument("--port", type=int, default=25)
    send.add_argument("--timeout", type=float, default=8)
    send.add_argument("--interval", type=float, default=1)
    send.add_argument("--allow-remote", action="store_true")
    send.add_argument("--starttls", action="store_true")
    send.add_argument("--output", required=True)
    recon = sub.add_parser("reconcile", help="require independently observed verdict for every accepted case")
    recon.add_argument("--report", required=True)
    recon.add_argument("--observations", required=True)
    recon.add_argument("--labels-out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "reconcile":
            count = reconcile(args)
            print(json.dumps({"status": "reconciled", "cases": count, "labels_out": args.labels_out,
                              "warning": "independent observations are not verified against server logs"}))
            return 0
        cases = load_manifest(args.manifest)
        if args.mode == "plan":
            print(json.dumps({"status": "validated_no_mail_sent", "cases": len(cases),
                              "ham": sum(x["label"] == "ham" for x in cases),
                              "spam": sum(x["label"] == "spam" for x in cases),
                              "cohorts": sorted({x["cohort"] for x in cases})}))
            return 0
        return run_send(args, cases)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"qualification refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
