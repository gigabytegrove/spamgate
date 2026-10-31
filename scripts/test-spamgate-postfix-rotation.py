"""End-to-end Postfix evidence correlation across compressed rotated logs."""
import gzip
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("spamgate-postfix-evidence.py")
RID = "a" * 32
DIGEST = "b" * 64
RECIPIENT = "test@example.org"
QUEUE = "A1B2C3"


class RotationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.report = self.root / "report.jsonl"
        self.output = self.root / "evidence.json"
        base = {"case_id": "ham1", "run_id": RID, "id": DIGEST,
                "label": "ham", "cohort": "direct"}
        rows = [{"event": "plan", "cases": 1},
                {**base, "event": "attempted"},
                {**base, "event": "smtp_accepted"}]
        self.report.write_text("\n".join(json.dumps(row) for row in rows) + "\n")

    def write(self, name, data, compress=False):
        path = self.root / name
        path.write_bytes(gzip.compress(data.encode()) if compress else data.encode())
        return path

    def invoke(self, *logs):
        command = [sys.executable, str(SCRIPT), "--report", str(self.report),
                   "--recipient", RECIPIENT, "--confirm-recipient", RECIPIENT,
                   "--output", str(self.output)]
        for path in logs:
            command.extend(("--postfix-log", str(path)))
        return subprocess.run(command, capture_output=True, text=True, timeout=15)

    def test_split_cleanup_transport_and_removal_across_rotation(self):
        old = self.write("mail.log.2.gz",
                         f"postfix/cleanup[123]: {QUEUE}: message-id=<{RID}@spamgate-qualification.invalid>\n",
                         compress=True)
        mid = self.write("mail.log.1.gz",
                         f"postfix/lmtp[124]: {QUEUE}: to=<{RECIPIENT}>, status=sent\n",
                         compress=True)
        current = self.write("mail.log",
                             f"postfix/qmgr[125]: {QUEUE}: removed\n")
        run = self.invoke(old, mid, current)
        self.assertEqual(run.returncode, 0, run.stderr)
        data = json.loads(self.output.read_text())
        self.assertTrue(data["complete_transport_correlation"])
        self.assertEqual(data["entries"][0]["state"],
                         "transport_sent_not_mailbox_verified")

    def test_corrupt_gzip_refuses_evidence_publication(self):
        log = self.root / "mail.log.1.gz"
        log.write_bytes(gzip.compress(b"postfix/cleanup[1]: A1B2C3: removed\n")[:-3])
        run = self.invoke(log)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertFalse(self.output.exists())

    def test_expanded_log_bomb_refuses_evidence_publication(self):
        log = self.root / "mail.log.1.gz"
        log.write_bytes(gzip.compress((b"x" * 1023 + b"\n") * 65536 + b"z"))
        run = self.invoke(log)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertFalse(self.output.exists())

    def test_reused_queue_id_across_rotation_is_ambiguous(self):
        old = self.write("mail.log.1.gz",
                         f"postfix/cleanup[123]: {QUEUE}: message-id=<{RID}@spamgate-qualification.invalid>\n"
                         f"postfix/lmtp[124]: {QUEUE}: to=<{RECIPIENT}>, status=sent\n"
                         f"postfix/qmgr[125]: {QUEUE}: removed\n", compress=True)
        current = self.write("mail.log",
                             f"postfix/cleanup[123]: {QUEUE}: message-id=<unrelated@example.org>\n")
        run = self.invoke(old, current)
        self.assertEqual(run.returncode, 3, run.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"],
                         "ambiguous_queue_identity")

    def test_symlinked_rotated_log_refused(self):
        original = self.write("real.log.gz", "not gzip")
        link = self.root / "mail.log.1.gz"
        link.symlink_to(original)
        run = self.invoke(link)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
