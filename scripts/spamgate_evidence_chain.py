"""Validate the Postfix-to-Maildir evidence handoff without trusting summary flags.

The input is operator-supplied, not cryptographically authenticated. This module
rejects internal contradictions before any Maildir is scanned.
"""
import re

RUN_ID = re.compile(r"[a-f0-9]{32}\Z")
QUEUE_ID = re.compile(r"[A-Za-z0-9]{5,32}\Z")
CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
ALLOWED_TRANSPORTS = frozenset(("smtp", "lmtp", "local", "virtual", "pipe"))
ALLOWED_STATUSES = frozenset(("sent", "deferred", "bounced"))
SUCCESS = "transport_sent_not_mailbox_verified"


def validate_transport_chain(evidence, entries):
    """Fail closed on contradictory counts, lifecycle and transport details.

    The chronology summary is retained as a distinct, non-authenticating
    provenance signal: legacy yearless or untimestamped logs may establish
    transport correlation but cannot prove chronological provenance.
    """
    if not isinstance(entries, list) or not entries:
        raise ValueError("missing transport evidence entries")
    counts = evidence.get("counts")
    if (not isinstance(counts, dict) or set(counts) != {SUCCESS}
            or type(counts[SUCCESS]) is not int or counts[SUCCESS] != len(entries)):
        raise ValueError("transport evidence counts contradict successful entries")
    chronology = evidence.get("log_chronology")
    if (not isinstance(chronology, dict)
            or type(chronology.get("chronology_validated")) is not bool
            or type(chronology.get("lines")) is not int
            or chronology["lines"] < len(entries)):
        raise ValueError("missing or invalid transport log chronology metadata")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid transport entry")
        rid, cid, qid = (entry.get("run_id"), entry.get("case_id"),
                         entry.get("queue_id"))
        if (not isinstance(rid, str) or not RUN_ID.fullmatch(rid)
                or not isinstance(cid, str) or not CASE_ID.fullmatch(cid)
                or not isinstance(qid, str) or not QUEUE_ID.fullmatch(qid)
                or entry.get("state") != SUCCESS
                or entry.get("queue_removed") is not True
                or entry.get("held") is not False
                or entry.get("discarded") is not False
                or type(entry.get("sent_count")) is not int
                or entry["sent_count"] != 1):
            raise ValueError("transport evidence has contradictory queue lifecycle")
        events = entry.get("transport_events")
        if not isinstance(events, list) or not events or len(events) > 64:
            raise ValueError("missing or unbounded recipient transport events")
        sent = 0
        for event in events:
            if (not isinstance(event, dict)
                    or set(event) != {"transport", "status"}
                    or not isinstance(event["transport"], str)
                    or not isinstance(event["status"], str)
                    or event["transport"] not in ALLOWED_TRANSPORTS
                    or event["status"] not in ALLOWED_STATUSES):
                raise ValueError("invalid or unsafe recipient transport event")
            if event["status"] == "bounced":
                raise ValueError("bounced recipient cannot qualify")
            if event["status"] == "sent":
                sent += 1
        if sent != 1:
            raise ValueError("transport events contradict sent count")
    return chronology["chronology_validated"]
