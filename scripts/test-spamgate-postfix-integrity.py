"""Postfix chronology and queue lifecycle regressions; synthetic logs only."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from spamgate_postfix_integrity import LogChronology

SCRIPT = pathlib.Path(__file__).with_name("spamgate-postfix-evidence.py")
RID = "a" * 32
DIGEST = "b" * 64
RECIPIENT = "test@example.org"
QUEUE = "A1B2C3"


class ChronologyTests(unittest.TestCase):
    def test_iso8601_with_offsets(self):
        checker = LogChronology()
        checker.observe("2026-10-31T14:00:00-04:00 postfix/cleanup[1]: event\n")
        checker.observe("2026-10-31T18:00:01Z postfix/lmtp[1]: event\n")
        self.assertTrue(checker.summary()["chronology_validated"])

    def test_rfc3164_december_to_january(self):
        checker = LogChronology()
        checker.observe("Dec 31 23:59:59 host postfix/cleanup[1]: event\n")
        checker.observe("Jan  1 00:00:01 host postfix/lmtp[1]: event\n")
        self.assertEqual(checker.summary()["yearless_rollovers"], 1)

    def test_rfc3164_out_of_order_refused(self):
        checker = LogChronology()
        checker.observe("Oct 31 15:00:00 host postfix/cleanup[1]: event\n")
        with self.assertRaisesRegex(ValueError, "chronology regressed"):
            checker.observe("Oct 31 14:00:00 host postfix/lmtp[1]: event\n")

    def test_iso8601_out_of_order_refused(self):
        checker = LogChronology()
        checker.observe("2026-10-31T14:00:10Z postfix/cleanup[1]: event\n")
        with self.assertRaisesRegex(ValueError, "chronology regressed"):
            checker.observe("2026-10-31T14:00:00Z postfix/lmtp[1]: event\n")

    def test_small_syslog_reorder_is_not_fully_validated(self):
        checker = LogChronology()
        checker.observe("Oct 31 15:00:02 host postfix/cleanup[1]: event\n")
        checker.observe("Oct 31 15:00:00 host postfix/lmtp[1]: event\n")
        self.assertFalse(checker.summary()["chronology_validated"])
        self.assertEqual(checker.summary()["tolerated_out_of_order_lines"], 1)

    def test_no_timestamps_is_explicitly_unverified(self):
        checker = LogChronology()
        checker.observe("postfix/lmtp[1]: A1B2C3: status=sent\n")
        self.assertFalse(checker.summary()["chronology_validated"])
        self.assertEqual(checker.summary()["untimestamped_lines"], 1)

    def test_mixed_formats_are_not_fully_validated(self):
        checker = LogChronology()
        checker.observe("Oct 31 15:00:00 host postfix/cleanup[1]: event\n")
        checker.observe("2026-10-31T15:00:01Z postfix/lmtp[1]: event\n")
        self.assertFalse(checker.summary()["chronology_validated"])

    def test_invalid_timestamp_refused(self):
        checker = LogChronology()
        with self.assertRaisesRegex(ValueError, "invalid ISO8601"):
            checker.observe("2026-13-31T15:00:01Z postfix/lmtp[1]: event\n")

    def test_second_year_rollover_refused(self):
        checker = LogChronology()
        for stamp in ("Dec 31 23:59:59", "Jan  1 00:00:01", "Dec 31 23:59:59"):
            checker.observe(stamp + " host postfix/cleanup[1]: event\n")
        with self.assertRaisesRegex(ValueError, "multiple year rollovers"):
            checker.observe("Jan  1 00:00:01 host postfix/lmtp[1]: event\n")


class QueueLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.report = self.root / "report.jsonl"
        self.log = self.root / "mail.log"
        self.output = self.root / "evidence.json"
        base = {"case_id": "ham1", "run_id": RID, "id": DIGEST,
                "label": "ham", "cohort": "direct"}
        self.report.write_text("\n".join(json.dumps(row) for row in (
            {"event": "plan", "cases": 1},
            {**base, "event": "attempted"},
            {**base, "event": "smtp_accepted"},
        )) + "\n")

    def invoke(self, lines):
        self.log.write_text("\n".join(lines) + "\n")
        return subprocess.run([
            sys.executable, str(SCRIPT), "--report", str(self.report),
            "--postfix-log", str(self.log), "--recipient", RECIPIENT,
            "--confirm-recipient", RECIPIENT, "--output", str(self.output)
        ], capture_output=True, text=True, timeout=15)

    def cleanup(self):
        return f"postfix/cleanup[1]: {QUEUE}: message-id=<{RID}@spamgate-qualification.invalid>"

    def sent(self):
        return f"postfix/lmtp[2]: {QUEUE}: to=<{RECIPIENT}>, status=sent"

    def removed(self):
        return f"postfix/qmgr[3]: {QUEUE}: removed"

    def state(self):
        return json.loads(self.output.read_text())["entries"][0]["state"]

    def test_unique_lifecycle_qualifies_transport_only(self):
        run = self.invoke([self.cleanup(), self.sent(), self.removed()])
        self.assertEqual(run.returncode, 0, run.stderr)
        data = json.loads(self.output.read_text())
        self.assertEqual(self.state(), "transport_sent_not_mailbox_verified")
        self.assertFalse(data["log_chronology"]["chronology_validated"])

    def test_repeated_cleanup_refused_as_ambiguous(self):
        run = self.invoke([self.cleanup(), self.sent(), self.removed(), self.cleanup()])
        self.assertEqual(run.returncode, 3, run.stderr)
        self.assertEqual(self.state(), "ambiguous_queue_identity")

    def test_repeated_queue_removal_refused(self):
        run = self.invoke([self.cleanup(), self.sent(), self.removed(), self.removed()])
        self.assertEqual(run.returncode, 3, run.stderr)
        self.assertEqual(self.state(), "ambiguous_queue_identity")

    def test_transport_after_removal_refused(self):
        run = self.invoke([self.cleanup(), self.sent(), self.removed(), self.sent()])
        self.assertEqual(run.returncode, 3, run.stderr)
        self.assertEqual(self.state(), "ambiguous_queue_identity")

    def test_hold_after_removal_refused(self):
        hold = f"postfix/cleanup[1]: {QUEUE}: hold: synthetic"
        run = self.invoke([self.cleanup(), self.sent(), self.removed(), hold])
        self.assertEqual(run.returncode, 3, run.stderr)
        self.assertEqual(self.state(), "ambiguous_queue_identity")

    def test_reversed_timestamped_logs_refused_without_evidence(self):
        run = self.invoke([
            "Oct 31 15:00:00 host " + self.cleanup(),
            "Oct 31 14:00:00 host " + self.sent(),
            "Oct 31 15:00:01 host " + self.removed(),
        ])
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertFalse(self.output.exists())

    def test_ordered_timestamped_logs_report_validated(self):
        run = self.invoke([
            "Oct 31 15:00:00 host " + self.cleanup(),
            "Oct 31 15:00:01 host " + self.sent(),
            "Oct 31 15:00:02 host " + self.removed(),
        ])
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(json.loads(self.output.read_text())["log_chronology"]["chronology_validated"])


if __name__ == "__main__":
    unittest.main()
