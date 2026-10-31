"""Fail-closed chronological integrity checks for operator-supplied Postfix logs.

These checks do not authenticate log provenance or establish mailbox receipt.
No host commands, queue actions, or network operations are performed.
"""
import datetime as dt
import re

ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)(?=\s)")
SYSLOG = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})(?=\s)")
TOLERANCE_SECONDS = 5


class LogChronology:
    """Validate nondecreasing timestamps across all supplied files.

    RFC3164 timestamps have no year or timezone. A single Dec-to-Jan
    transition is permitted, but the resulting ordering remains partial.
    Missing timestamps and mixed formats are explicitly reported.
    """

    def __init__(self):
        self.lines = 0
        self.timestamped = 0
        self.untimestamped = 0
        self.formats = set()
        self.last = {}
        self.last_syslog_month = None
        self.syslog_rollovers = 0
        self.backward_tolerance_events = 0

    def observe(self, line):
        self.lines += 1
        match = ISO.match(line)
        if match:
            mode = "iso8601"
            try:
                timestamp = dt.datetime.fromisoformat(match.group(1).replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("invalid ISO8601 Postfix log timestamp") from exc
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=dt.timezone.utc)
            value = timestamp.timestamp()
        else:
            match = SYSLOG.match(line)
            if match:
                mode = "rfc3164"
                month_name, day, clock = match.groups()
                try:
                    timestamp = dt.datetime.strptime(
                        f"2000 {month_name} {day} {clock}", "%Y %b %d %H:%M:%S"
                    )
                except ValueError as exc:
                    raise ValueError("invalid RFC3164 Postfix log timestamp") from exc
                if self.last_syslog_month == 12 and timestamp.month == 1:
                    self.syslog_rollovers += 1
                    if self.syslog_rollovers > 1:
                        raise ValueError("multiple year rollovers in yearless Postfix logs")
                self.last_syslog_month = timestamp.month
                value = timestamp.timetuple().tm_yday * 86400 + (
                    timestamp.hour * 3600 + timestamp.minute * 60 + timestamp.second
                ) + self.syslog_rollovers * 366 * 86400
            else:
                self.untimestamped += 1
                return

        previous = self.last.get(mode)
        if previous is not None and value < previous:
            delta = previous - value
            if delta > TOLERANCE_SECONDS:
                raise ValueError(
                    f"Postfix log chronology regressed by {delta:.0f} seconds "
                    f"at input line {self.lines}; supply logs oldest first"
                )
            self.backward_tolerance_events += 1
            # A tolerated out-of-order syslog line must not move the high-water mark.
            value = previous
        self.last[mode] = value
        self.timestamped += 1
        self.formats.add(mode)

    def summary(self):
        return {
            "lines": self.lines,
            "timestamped_lines": self.timestamped,
            "untimestamped_lines": self.untimestamped,
            "formats": sorted(self.formats),
            "yearless_rollovers": self.syslog_rollovers,
            "tolerated_out_of_order_lines": self.backward_tolerance_events,
            "chronology_validated": (
                self.timestamped > 0
                and self.untimestamped == 0
                and len(self.formats) == 1
                and self.backward_tolerance_events == 0
            ),
            "limitation": (
                "RFC3164 timestamps lack a year/timezone; ISO timestamps without "
                "an offset are compared as UTC; no log-source authenticity is proven"
            ),
        }
