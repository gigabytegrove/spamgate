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

from spamgate_log_reader import bounded_log_lines
from spamgate_postfix_integrity import LogChronology

MAX_CASES = 1000
MAX_LOGS = 16
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 65536
QUEUE = r"[A-Za-z0-9]{5,32}"
CLEANUP = re.compile(r"\bpostfix/cleanup\[\d+\]: (" + QUEUE + r"): message-id=<([a-f0-9]{32})@spamgate-qualification\.invalid>", re.I)
CLEANUP_ANY = re.compile(r"\bpostfix/cleanup\[\d+\]: (" + QUEUE + r"): message-id=<([^<>]+)>", re.I)
EVENT = re.compile(r"\bpostfix/(smtp|lmtp|local|virtual|pipe|error|discard)\[\d+\]: (" + QUEUE + r"): to=<([^<>\s]+)>.*?\bstatus=([a-z][a-z_-]{0,31})\b", re.I)
DSN = re.compile(r"(?<![A-Za-z0-9_])dsn=([0-9])\\.([0-9]{1,3})\\.([0-9]{1,3})(?![0-9])", re.I)
REMOVED = re.compile(r"\bpostfix/qmgr\[\d+\]: (" + QUEUE + r"): removed\b", re.I)
QMGR_RECIPIENTS = re.compile(r"\bpostfix/qmgr\[\d+\]: (" + QUEUE + r"): from=<[^<>]*>,[^\r\n]*?\bnrcpt=(\d+)\b", re.I)
HOLD = re.compile(r"\bpostfix/(?:cleanup|smtpd)\[\d+\]: (" + QUEUE + r"):.*\bhold:\s", re.I)
RUN_ID = re.compile(r"[a-f0-9]{32}\Z")
CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
COHORTS = {"direct", "forwarded", "attachment", "internationalized", "bulk", "other"}


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate qualification JSON key")
        result[key] = value
    return result


def reject_json_constant(value):
    raise ValueError("non-finite qualification JSON number")


def stable_report_identity(before, after):
    return (stat.S_ISREG(after.st_mode) and
            os.path.samestat(before, after) and
            before.st_size == after.st_size and
            before.st_mtime_ns == after.st_mtime_ns and
            before.st_ctime_ns == after.st_ctime_ns)


def read_jsonl(path, limit):
    # A qualification report is untrusted operator-supplied input. Never
    # follow a symlink, and never read an arbitrarily large line into memory
    # before applying the JSONL size limit.
    target = pathlib.Path(path)
    before = target.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit * MAX_LINE_BYTES:
        raise ValueError("report must be a bounded regular file")
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    result = []
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stable_report_identity(before, opened):
            raise ValueError("report identity changed during open")
        number = 0
        while True:
            raw = handle.readline(MAX_LINE_BYTES + 1)
            if not raw:
                break
            number += 1
            if len(raw) > MAX_LINE_BYTES:
                raise ValueError(f"JSONL line {number} exceeds size limit")
            if not raw.strip():
                continue
            if len(result) >= limit:
                raise ValueError("JSONL record limit exceeded")
            value = json.loads(raw, object_pairs_hook=unique_json_object,
                               parse_constant=reject_json_constant)
            if not isinstance(value, dict):
                raise ValueError(f"JSONL line {number} must be an object")
            result.append(value)
        after = os.fstat(handle.fileno())
        try:
            current_path = target.lstat()
        except FileNotFoundError as exc:
            raise ValueError("qualification report changed during read") from exc
        if (not stable_report_identity(opened, after) or
                not stable_report_identity(opened, current_path)):
            raise ValueError("qualification report changed during read")
    return result

def accepted_runs(path):
    rows = read_jsonl(path, 2 * MAX_CASES + 1)
    if not rows or set(rows[0]) != {"event", "cases"} or rows[0]["event"] != "plan":
        raise ValueError("invalid qualification plan")
    count = rows[0]["cases"]
    if type(count) is not int or not 1 <= count <= MAX_CASES:
        raise ValueError("invalid planned case count")
    attempts, outcomes, ids, fixture_digests = {}, {}, set(), set()
    for row in rows[1:]:
        event, cid, rid = row.get("event"), row.get("case_id"), row.get("run_id")
        # Reject malformed identity fields before accepting an SMTP submission
        # as evidence. These values also appear in the published report.
        if (not isinstance(cid, str) or not CASE_ID.fullmatch(cid)
                or not isinstance(rid, str) or not RUN_ID.fullmatch(rid)):
            raise ValueError("invalid report case or run ID")
        if (not isinstance(row.get("label"), str) or
                row["label"] not in ("ham", "spam") or
                not isinstance(row.get("cohort"), str) or
                not row["cohort"] in COHORTS):
            raise ValueError("invalid report label or cohort")
        if event == "attempted":
            if cid in attempts or rid in ids:
                raise ValueError("duplicate attempt identity")
            if not isinstance(row.get("id"), str) or not re.fullmatch(r"[a-f0-9]{64}", row["id"]):
                raise ValueError("invalid fixture digest")
            # Reusing one fixture across cases inflates the apparent independent
            # sample size and can falsely satisfy corpus qualification gates.
            if row["id"] in fixture_digests:
                raise ValueError("duplicate qualification fixture digest")
            attempts[cid] = row
            ids.add(rid)
            fixture_digests.add(row["id"])
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
    yield from bounded_log_lines(path)


def correlate(report, paths, recipient, chronology=None):
    attempts = accepted_runs(report)
    runs = {row["run_id"]: row for row in attempts.values()}
    queue_to_run = {}
    entries = {rid: {"case_id": row["case_id"], "run_id": rid,
                     "queue_id": None, "transport_events": [], "queue_removed": False,
                     "held": False, "sent_count": 0, "discarded": False, "state": "unobserved"} for rid, row in runs.items()}
    duplicate = set()
    # qmgr can log its envelope count before cleanup appears in a rotated
    # or merged evidence stream. Retain it and refuse contradictory counts.
    qmgr_counts = {}
    # Transport, HOLD and removal records preceding cleanup cannot safely be
    # assigned to the subsequently observed message. A queue ID may be reused.
    pre_cleanup_activity = set()
    foreign_cleanup = set()
    for path in paths:
        for line in log_lines(path):
            if chronology is not None:
                chronology.observe(line)
            cleanup = CLEANUP.search(line)
            if cleanup:
                queue_id, rid = cleanup.group(1), cleanup.group(2).lower()
                if rid not in entries:
                    # A qualification-shaped Message-ID from another run is
                    # foreign cleanup, not evidence for this qualification.
                    if queue_id in queue_to_run:
                        duplicate.add(queue_to_run[queue_id])
                    else:
                        foreign_cleanup.add(queue_id)
                    continue
                if rid in entries:
                    previous = entries[rid]["queue_id"]
                    if previous is not None:
                        # Repeated cleanup identities can be rotation overlap or
                        # a queue lifecycle replay; neither qualifies as unique.
                        duplicate.add(rid)
                    other = queue_to_run.get(queue_id)
                    if other is not None and other != rid:
                        duplicate.update((rid, other))
                    queue_to_run[queue_id] = rid
                    entries[rid]["queue_id"] = queue_id
                    if queue_id in pre_cleanup_activity or queue_id in foreign_cleanup:
                        duplicate.add(rid)
                    if queue_id in qmgr_counts and qmgr_counts[queue_id] != {1}:
                        duplicate.add(rid)
                continue
            other_cleanup = CLEANUP_ANY.search(line)
            if other_cleanup and other_cleanup.group(1) not in queue_to_run:
                foreign_cleanup.add(other_cleanup.group(1))
            if other_cleanup and other_cleanup.group(1) in queue_to_run:
                # Queue IDs can be reused after a completed delivery. A later
                # unrelated cleanup must never lend its status to an old run.
                duplicate.add(queue_to_run[other_cleanup.group(1)])
                continue
            qmgr = QMGR_RECIPIENTS.search(line)
            if qmgr:
                queue_id, nrcpt = qmgr.groups()
                qmgr_counts.setdefault(queue_id, set()).add(int(nrcpt))
                rid = queue_to_run.get(queue_id)
                if rid is not None:
                    # A single-recipient probe cannot certify a queue whose
                    # envelope had multiple recipients, even when logs omit
                    # transport lines for the additional recipients.
                    if entries[rid]["queue_removed"] or qmgr_counts[queue_id] != {1}:
                        duplicate.add(rid)
                continue
            event = EVENT.search(line)
            if event:
                transport, queue_id, address, status = event.groups()
                rid = queue_to_run.get(queue_id)
                if rid is None:
                    pre_cleanup_activity.add(queue_id)
                # Even a different recipient after removal indicates a
                # reused/overlapping queue identity: never certify this run.
                if rid is not None and entries[rid]["queue_removed"]:
                    duplicate.add(rid)
                if rid is not None and address != recipient:
                    # A single-recipient qualification cannot certify a queue
                    # whose actual transport includes other recipients. In
                    # particular, "sent" for the target must not hide a
                    # different recipient's deferred/bounced disposition.
                    duplicate.add(rid)
                # Postfix DSN class and textual status must agree. A forged,
                # malformed or contradictory enhanced status is not proof of
                # successful delivery. Absence of DSN is allowed for older logs.
                dsn_fields = re.findall(r"(?<![A-Za-z0-9_])dsn=([^,\\s()]+)", line, re.I)
                expected_class = {"sent": "2", "deferred": "4", "bounced": "5"}.get(status.lower())
                if rid is not None and dsn_fields:
                    parsed = DSN.fullmatch("dsn=" + dsn_fields[0])
                    if (len(dsn_fields) != 1 or parsed is None or
                            expected_class is None or parsed.group(1) != expected_class):
                        duplicate.add(rid)
                if rid is not None and status.lower() not in ("sent", "deferred", "bounced"):
                    # Unknown outcomes cannot be silently ignored when certifying delivery.
                    duplicate.add(rid)
                if rid is not None and address == recipient:
                    item = {"transport": transport.lower(), "status": status.lower()}
                    if item["transport"] in ("discard", "error"):
                        entries[rid]["discarded"] = True
                    if item["status"] == "sent":
                        entries[rid]["sent_count"] += 1
                    if item not in entries[rid]["transport_events"]:
                        entries[rid]["transport_events"].append(item)
                continue
            removed = REMOVED.search(line)
            if removed and removed.group(1) not in queue_to_run:
                pre_cleanup_activity.add(removed.group(1))
            if removed and removed.group(1) in queue_to_run:
                rid = queue_to_run[removed.group(1)]
                if entries[rid]["queue_removed"]:
                    duplicate.add(rid)
                entries[rid]["queue_removed"] = True
                continue
            hold = HOLD.search(line)
            if hold and hold.group(1) not in queue_to_run:
                pre_cleanup_activity.add(hold.group(1))
            if hold and hold.group(1) in queue_to_run:
                rid = queue_to_run[hold.group(1)]
                if entries[rid]["queue_removed"]:
                    duplicate.add(rid)
                entries[rid]["held"] = True
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
            # A definitive bounced recipient must not be hidden by the
            # postfix/error transport classification. Both are failures,
            # but bounce is the more specific actionable terminal state.
            entry["state"] = "bounced"
        elif entry["discarded"]:
            entry["state"] = "discard_or_error_transport"
        elif "sent" in statuses and "deferred" in statuses:
            # A later successful retry can follow a transient deferral, but
            # the logs alone cannot prove the events belong to one intact
            # queue lifecycle. Require an unambiguous terminal disposition.
            entry["state"] = "mixed_transport_status_unverified"
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
        chronology = LogChronology()
        entries = correlate(args.report, args.postfix_log, args.recipient, chronology)
        states = {}
        for entry in entries:
            states[entry["state"]] = states.get(entry["state"], 0) + 1
        complete = all(entry["state"] == "transport_sent_not_mailbox_verified" for entry in entries)
        result = {"schema": 1, "type": "postfix_transport_evidence_only", "recipient": args.recipient, "complete_transport_correlation": complete,
                  "counts": states, "entries": entries,
                  "log_chronology": chronology.summary(),
                  "limitations": ["Postfix status=sent does not prove Dovecot INBOX/Junk placement",
                                  "No SpamGate classifier verdicts are inferred",
                                  "Input logs and mailbox identity are operator supplied, not cryptographically authenticated",
                                  "Missing or mixed-format log timestamps do not establish chronological provenance"]}
        publish(args.output, result)
        print(json.dumps({"output": args.output, "cases": len(entries), "complete_transport_correlation": complete, "counts": states}))
        return 0 if complete else 3
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Postfix evidence refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
