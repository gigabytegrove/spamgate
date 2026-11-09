"""Qualification report integrity regressions; no live mail server required."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("spamgate-postfix-evidence.py")
RUN = "a" * 32
DIGEST = "b" * 64
RECIPIENT = "test@example.org"


class ReportIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.report = self.root / "report.jsonl"
        self.log = self.root / "mail.log"
        self.output = self.root / "evidence.json"
        self.log.write_text("")
        base = {"case_id": "clean", "run_id": RUN, "id": DIGEST,
                "label": "ham", "cohort": "direct"}
        self.rows = [{"event": "plan", "cases": 1},
                     dict(base, event="attempted"),
                     dict(base, event="smtp_accepted")]
        self.write_rows()

    def write_rows(self):
        self.report.write_text("".join(json.dumps(row) + "\n" for row in self.rows))

    def invoke(self):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--report", str(self.report),
             "--postfix-log", str(self.log), "--recipient", RECIPIENT,
             "--confirm-recipient", RECIPIENT, "--output", str(self.output)],
            capture_output=True, text=True, timeout=10)

    def assert_refused(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.output.exists())

    def test_duplicate_plan_key_refused(self):
        self.report.write_text('{"event":"plan","cases":1,"cases":1}\n' +
                               "".join(json.dumps(row) + "\n" for row in self.rows[1:]))
        self.assert_refused()

    def test_duplicate_attempt_identity_key_refused(self):
        rows = self.report.read_text().splitlines()
        rows[1] = rows[1].replace('"run_id":', '"run_id":"c", "run_id":')
        self.report.write_text("\n".join(rows) + "\n")
        self.assert_refused()

    def test_nonfinite_number_refused(self):
        self.report.write_text(self.report.read_text().replace('"cases": 1', '"cases": NaN'))
        self.assert_refused()

    def test_infinite_number_refused(self):
        self.report.write_text(self.report.read_text().replace('"cases": 1', '"cases": Infinity'))
        self.assert_refused()

    def test_valid_report_is_parsed_but_not_falsely_qualified(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertTrue(self.output.exists())
        evidence = json.loads(self.output.read_text())
        self.assertFalse(evidence["complete_transport_correlation"])

    def test_symlink_report_refused(self):
        original = self.root / "original.jsonl"
        self.report.rename(original)
        self.report.symlink_to(original)
        self.assert_refused()


if __name__ == "__main__":
    unittest.main()
