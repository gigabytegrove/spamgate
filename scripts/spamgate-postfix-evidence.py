#!/usr/bin/env python3
"""Read-only, bounded Postfix transport evidence for native SpamGate corpus runs.

Transport status=sent is NOT a classifier verdict or verified Dovecot mailbox delivery.
Supply rotated logs oldest first; no Postfix/Dovecot configuration is modified.
"""
import argparse
import json
import os
import pathlib
import re
import stat
import sys

MAX_CASES = 1000
MAX_LOGS = 16
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 65536
QUEUE = r"[A-Za-z0-9]{5,32}"
CLEANUP = re.compile(r"\bpostfix/cleanup\[\d+\]: (" + QUEUE + r"): message-id=<([a-f0-9]{32})@spamgate-qualification\.invalid>", re.I)
CLEANUP_ANY = re.compile(r"\bpostfix/cleanup\[\d+\]: (" + QUEUE + r"): message-id=<([^<>]+)>", re.I)
EVENT = re.compile(r"\bpostfix/(smtp|lmtp|local|virtual|pipe|error|discard)\[\d+\]: (" + QUEUE + r"): to=<([^<>\s]+)>.*?\bstatus=(sent|deferred|bounced)\b", re.I)
REMOVED = re.compile(r"\bpostfix/qmgr\[\d+\]: (" + QUEUE + r"): removed\b", re.I)
HOLD = re.compile(r"\bpostfix/(?:cleanup|smtpd)\[\d+\]: (" + QUEUE + r"):.*\bhold:\s", re.I)
RUN_ID = re.compile(r"[a-f0-9]{32}\Z")


def read_jsonl(path, limit):
    result = []
    with open(path, "rb") as handle:
        for number, raw in enumerate(handle, 1):
            if len(raw) > MAX_LINE_BYTES:
                raise ValueError(f"JSONL line {number} exceeds size limit")
            if not raw.strip():
                continue
            if len(result) >= limit:
                raise ValueError("JSONL record limit exceeded")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError(f"JSONL line {number} must be an object")
            result.append(value)
    return result


def accepted_runs(path):
    rows = read_jsonl(path, 2 * MAX_CASES + 1)
    if not rows or set(rows[0]) != {"event", "cases"} or rows[0]["event"] != "plan":
        raise ValueError("invalid qualification plan")
    count = rows[0]["cases"]
    if type(count) is not int or not 1 <= count <= MAX_CASES:
        raise ValueError("invalid planned case count")
    attempts, outcomes, ids = {}, {}, set()
    for row in rows[1:]:
        event, cid, rid = row.get("event"), row.get("case_id"), row.get("run_id")
        if not isinstance(cid, str) or not isinstance(rid, str) or not RUN_ID.fullmatch(rid):
            raise ValueError("invalid report case or run ID")
        if event == "attempted":
            if cid in attempts or rid in ids:
                raise ValueError("duplicate attempt identity")
            if not isinstance(row.get("id"), str) or not re.fullmatch(r"[a-f0-9]{64}", row["id"]):
                raise ValueError("invalid fixture digest")
            attempts[cid] = row
            ids.add(rid)
        elif event in ("smtp_accepted", "failed"):
            if cid not in attempts or cid in outcomes:
                raise ValueError("terminal result missing attempt or duplicated")
            if any(row.get(key) != attempts[cid].get(key) for key in ("case_id", "run_id", "id", "label", "cohort")):
                raise ValueError("terminal result identity mismatch")
            outcomes[cid] = event
        else:
            raise ValueError("unexpected report event")
    if len(attempts) != count or len(outcomes) != count or set(outcomes.values()) != {"smtp_accepted"}:
        raise ValueError("incomplete or failed submission cannot qualify")
    return attempts


def log_lines(path):
    target = pathlib.Path(path)
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LOG_BYTES:
        raise ValueError("log must be a regular file within 64 MiB")
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_LOG_BYTES:
            raise ValueError("log changed or exceeds 64 MiB")
        total = 0
        while True:
            raw = handle.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            total += len(raw)
            if len(raw) > MAX_LINE_BYTES or total > MAX_LOG_BYTES:
                raise ValueError("oversized Postfix log line or file")
            yield raw.decode("utf-8", "replace")


def correlate(report, paths, recipient):
    attempts = accepted_runs(report)
    runs = {row["run_id"]: row for row in attempts.values()}
    queue_to_run = {}
    entries = {rid: {"case_id": row["case_id"], "run_id": rid,
                     "queue_id": None, "transport_events": [], "queue_removed": False,
                     "held": False, "sent_count": 0, "state": "unobserved"} for rid, row in runs.items()}
    duplicate = set()
    for path in paths:
        for line in log_lines(path):
            cleanup = CLEANUP.search(line)
            if cleanup:
                queue_id, rid = cleanup.group(1), cleanup.group(2).lower()
                if rid in entries:
                    previous = entries[rid]["queue_id"]
                    if previous is not None and previous != queue_id:
                        duplicate.add(rid)
                    other = queue_to_run.get(queue_id)
                    if other is not None and other != rid:
                        duplicate.update((rid, other))
                    queue_to_run[queue_id] = rid
                    entries[rid]["queue_id"] = queue_id
                continue
            other_cleanup = CLEANUP_ANY.search(line)
            if other_cleanup and other_cleanup.group(1) in queue_to_run:
                # Queue IDs can be reused after a completed delivery. A later
                # unrelated cleanup must never lend its status to an old run.
                duplicate.add(queue_to_run[other_cleanup.group(1)])
                continue
            event = EVENT.search(line)
            if event:
                transport, queue_id, address, status = event.groups()
                rid = queue_to_run.get(queue_id)
                if rid is not None and address == recipient:
                    item = {"transport": transport.lower(), "status": status.lower()}
                    if item["status"] == "sent":
                        entries[rid]["sent_count"] += 1
                    if item not in entries[rid]["transport_events"]:
                        entries[rid]["transport_events"].append(item)
                continue
            removed = REMOVED.search(line)
            if removed and removed.group(1) in queue_to_run:
                entries[queue_to_run[removed.group(1)]]["queue_removed"] = True
                continue
            hold = HOLD.search(line)
            if hold and hold.group(1) in queue_to_run:
                entries[queue_to_run[hold.group(1)]]["held"] = True
    for rid, entry in entries.items():
        statuses = {event["status"] for event in entry["transport_events"]}
        if rid in duplicate:
            entry["state"] = "ambiguous_queue_identity"
        elif entry["queue_id"] is None:
            entry["state"] = "no_cleanup_correlation"
        elif entry["held"]:
            entry["state"] = "held_unverified"
        elif entry["sent_count"] > 1:
            entry["state"] = "duplicate_transport_sent"
        elif "bounced" in statuses:
            entry["state"] = "bounced"
        elif "sent" in statuses and entry["queue_removed"]:
            entry["state"] = "transport_sent_not_mailbox_verified"
        elif "sent" in statuses:
            entry["state"] = "sent_but_queue_removal_unobserved"
        elif "deferred" in statuses:
            entry["state"] = "deferred"
        else:
            entry["state"] = "no_matching_recipient_transport"
    return [entries[row["run_id"]] for row in attempts.values()]


def publish(path, report):
    target = pathlib.Path(path)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, help="qualification send report JSONL")
    parser.add_argument("--postfix-log", action="append", required=True, help="repeat in chronological order")
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--confirm-recipient", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if not 1 <= len(args.postfix_log) <= MAX_LOGS:
            raise ValueError("Postfix log count must be 1..16")
        if args.recipient != args.confirm_recipient or not re.fullmatch(r"[^<>\s@]+@[^<>\s@]+", args.recipient):
            raise ValueError("recipient confirmation mismatch or invalid address")
        if len(set(args.postfix_log)) != len(args.postfix_log):
            raise ValueError("duplicate log path")
        entries = correlate(args.report, args.postfix_log, args.recipient)
        states = {}
        for entry in entries:
            states[entry["state"]] = states.get(entry["state"], 0) + 1
        complete = all(entry["state"] == "transport_sent_not_mailbox_verified" for entry in entries)
        result = {"schema": 1, "type": "postfix_transport_evidence_only", "complete_transport_correlation": complete,
                  "counts": states, "entries": entries,
                  "limitations": ["Postfix status=sent does not prove Dovecot INBOX/Junk placement",
                                  "No SpamGate classifier verdicts are inferred",
                                  "Input logs and mailbox identity are operator supplied, not cryptographically authenticated"]}
        publish(args.output, result)
        print(json.dumps({"output": args.output, "cases": len(entries), "complete_transport_correlation": complete, "counts": states}))
        return 0 if complete else 3
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Postfix evidence refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
