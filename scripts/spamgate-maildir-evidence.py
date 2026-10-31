#!/usr/bin/env python3
"""Read-only Maildir placement evidence for independently correlated SpamGate test runs.

This verifies observable Maildir file placement only, not IMAP/mdbox storage,
classifier correctness, user-visible IMAP state, or production host qualification.
"""
import argparse
import contextlib
import json
import os
import pathlib
import re
import stat
import sys
from email import policy
from email.parser import BytesHeaderParser

MAX_REPORT = 2 * 1024 * 1024
MAX_CASES = 1000
MAX_FILES = 20000
MAX_MESSAGE = 64 * 1024 * 1024
MAX_HEADERS = 128 * 1024
RUN_ID = re.compile(r"[a-f0-9]{32}\Z")
ADDRESS = re.compile(r"[^<>\s@]+@[^<>\s@]+\Z")


def regular_fd(path, max_bytes):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
        os.close(fd)
        raise ValueError(f"not a bounded regular file: {path}")
    return fd


def read_evidence(path, recipient):
    with os.fdopen(regular_fd(path, MAX_REPORT), "rb") as handle:
        raw = handle.read(MAX_REPORT + 1)
    if len(raw) > MAX_REPORT:
        raise ValueError("transport evidence exceeds limit")
    evidence = json.loads(raw)
    if (not isinstance(evidence, dict) or evidence.get("schema") != 1
            or evidence.get("type") != "postfix_transport_evidence_only"
            or evidence.get("complete_transport_correlation") is not True
            or evidence.get("recipient") != recipient):
        raise ValueError("transport evidence incomplete, incompatible, or for another recipient")
    entries = evidence.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_CASES:
        raise ValueError("invalid transport evidence entries")
    runs, cases, queues = set(), set(), set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid transport entry")
        rid, cid, queue = entry.get("run_id"), entry.get("case_id"), entry.get("queue_id")
        if (not isinstance(rid, str) or not RUN_ID.fullmatch(rid)
                or not isinstance(cid, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", cid)
                or not isinstance(queue, str) or not re.fullmatch(r"[A-Za-z0-9]{5,32}", queue)
                or entry.get("state") != "transport_sent_not_mailbox_verified"
                or rid in runs or cid in cases or queue in queues):
            raise ValueError("ambiguous or invalid transport correlation")
        runs.add(rid)
        cases.add(cid)
        queues.add(queue)
    return entries


def directory(path):
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError(f"not a real directory: {path}")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    if not stat.S_ISDIR(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError(f"directory changed: {path}")
    return fd


@contextlib.contextmanager
def open_directory(path):
    fd = directory(path)
    try:
        yield fd
    finally:
        os.close(fd)


def message_id(dir_fd, filename):
    fd = os.open(filename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MESSAGE:
            raise ValueError("nonregular or oversized Maildir entry")
        header = bytearray()
        while len(header) <= MAX_HEADERS:
            line = handle.readline(MAX_HEADERS + 1 - len(header))
            if not line or line in (b"\n", b"\r\n"):
                break
            header.extend(line)
        else:
            raise ValueError("Maildir headers exceed limit")
        if len(header) > MAX_HEADERS:
            raise ValueError("Maildir headers exceed limit")
        msg = BytesHeaderParser(policy=policy.default).parsebytes(bytes(header) + b"\r\n")
        values = msg.get_all("Message-ID", [])
        if len(values) != 1:
            return None
        value = str(values[0]).strip()
        match = re.fullmatch(r"<([a-f0-9]{32})@spamgate-qualification\.invalid>", value)
        return match.group(1) if match else None


def scan_maildir(root, placement, hits, limit):
    with open_directory(root) as root_fd:
        for folder in ("new", "cur"):
            with open_directory(os.path.join(root, folder)) as folder_fd:
                with os.scandir(folder_fd) as listing:
                    for item in listing:
                        limit[0] += 1
                        if limit[0] > MAX_FILES:
                            raise ValueError("Maildir entry limit exceeded")
                        if not item.is_file(follow_symlinks=False):
                            raise ValueError("Maildir contains symlink or non-file entry")
                        rid = message_id(folder_fd, item.name)
                        if rid in hits:
                            hits[rid].append({"folder": placement, "state": folder})


def publish(path, data):
    target = pathlib.Path(path)
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        with open_directory(target.parent) as parent_fd:
            os.fsync(parent_fd)
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def run(args):
    if (args.recipient != args.confirm_recipient or not ADDRESS.fullmatch(args.recipient)):
        raise ValueError("invalid recipient or confirmation mismatch")
    entries = read_evidence(args.transport_evidence, args.recipient)
    inbox = pathlib.Path(args.inbox_maildir)
    junk = pathlib.Path(args.junk_maildir)
    if inbox.resolve() == junk.resolve():
        raise ValueError("INBOX and Junk must be distinct Maildirs")
    hits = {row["run_id"]: [] for row in entries}
    limit = [0]
    scan_maildir(inbox, "INBOX", hits, limit)
    scan_maildir(junk, "Junk", hits, limit)
    result = []
    counts = {"inbox": 0, "junk": 0, "missing": 0, "duplicate": 0}
    for row in entries:
        locations = hits[row["run_id"]]
        state = ("missing" if not locations else "duplicate" if len(locations) > 1
                 else "inbox" if locations[0]["folder"] == "INBOX" else "junk")
        counts[state] += 1
        result.append({"case_id": row["case_id"], "run_id": row["run_id"],
                       "queue_id": row["queue_id"], "state": state, "locations": locations})
    complete = counts["missing"] == 0 and counts["duplicate"] == 0
    publish(args.output, {"schema": 1, "type": "maildir_file_placement_only", "recipient": args.recipient,
                          "complete_maildir_correlation": complete, "counts": counts,
                          "scanned_entries": limit[0], "entries": result,
                          "limitations": ["Only operator-selected Maildir/new and cur paths were inspected",
                                          "Maildir placement does not independently prove Dovecot IMAP visibility",
                                          "Classifier verdict, Sieve policy, and test-label correctness not assessed"]})
    print(json.dumps({"output": args.output, "complete_maildir_correlation": complete, "counts": counts}))
    return 0 if complete else 3


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport-evidence", required=True)
    parser.add_argument("--inbox-maildir", required=True)
    parser.add_argument("--junk-maildir", required=True)
    parser.add_argument("--recipient", required=True)
    parser.add_argument("--confirm-recipient", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        return run(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Maildir evidence refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
