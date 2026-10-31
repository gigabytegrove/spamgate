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
CASE_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\Z")


def load_jsonl(path, limit):
    records = []
    with open(path, "rb") as handle:
        for number, raw in enumerate(handle, 1):
            if len(raw) > 65536:
                raise ValueError(f"{path}: line {number} exceeds 64 KiB")
            if not raw.strip():
                continue
            if len(records) >= limit:
                raise ValueError(f"{path}: exceeds {limit} records")
            record = json.loads(raw)
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
    if not events or set(events[0]) != {"event", "cases"} or events[0]["event"] != "plan" or type(events[0]["cases"]) is not int or not 1 <= events[0]["cases"] <= MAX_CASES:
        raise ValueError("missing or invalid durable batch plan")
    planned_count = events[0]["cases"]
    events = events[1:]
    observed = load_jsonl(args.observations, MAX_CASES)
    attempts, accepted, failed = {}, set(), set()
    for row in events:
        if set(row) - {"case_id", "id", "label", "cohort", "run_id", "event", "error"}:
            raise ValueError("unexpected report fields")
        cid, run_id, event = row.get("case_id"), row.get("run_id"), row.get("event")
        if not isinstance(cid, str) or not isinstance(run_id, str):
            raise ValueError("invalid report identity")
        if event == "attempted":
            if cid in attempts or run_id in {x["run_id"] for x in attempts.values()}:
                raise ValueError("duplicate attempted case or run ID")
            attempts[cid] = row
        elif event in ("smtp_accepted", "failed"):
            if cid not in attempts or any(row.get(k) != attempts[cid].get(k) for k in ("case_id", "id", "label", "cohort", "run_id")):
                raise ValueError("result without matching attempt")
            if cid in accepted or cid in failed:
                raise ValueError("duplicate terminal event")
            (accepted if event == "smtp_accepted" else failed).add(cid)
        else:
            raise ValueError("invalid report event")
    if len(attempts) != planned_count or len(accepted) != planned_count or failed:
        raise ValueError("incomplete or failed SMTP intake: no classifier qualification")
    observations = {}
    for row in observed:
        if set(row) != {"run_id", "action"} or row["action"] not in ACTIONS:
            raise ValueError("observation requires only run_id and actual action")
        if row["run_id"] in observations:
            raise ValueError("duplicate observed run ID")
        observations[row["run_id"]] = row["action"]
    if set(observations) != {x["run_id"] for x in attempts.values()}:
        raise ValueError("missing or unrelated observed actions; no implicit accept verdicts")
    rows = []
    seen = set()
    for case in attempts.values():
        if case["id"] in seen or not re.fullmatch(r"[0-9a-f]{64}", str(case["id"])):
            raise ValueError("invalid or duplicated SHA-256 fixture identity")
        seen.add(case["id"])
        if case["label"] not in ("ham", "spam") or case["cohort"] not in COHORTS:
            raise ValueError("invalid label or cohort in report")
        rows.append({"id": case["id"], "label": case["label"],
                     "cohort": case["cohort"], "action": observations[case["run_id"]]})
    with exclusive_output(args.labels_out) as output:
        for row in rows:
            record(output, row)
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
