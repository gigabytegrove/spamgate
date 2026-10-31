"""Isolated Maildir file-placement evidence tests; no live mail services."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("spamgate-maildir-evidence.py")
RID1 = "a" * 32
RID2 = "b" * 32
RECIPIENT = "spambox@example.org"


class MaildirEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.inbox = self.root / "Maildir"
        self.junk = self.inbox / ".Junk"
        for base in (self.inbox, self.junk):
            for name in ("cur", "new"):
                (base / name).mkdir(parents=True)
        self.evidence = self.root / "transport.json"
        self.output = self.root / "maildir.json"
        self.write_evidence([RID1])

    def write_evidence(self, ids, **overrides):
        data = {"schema": 1, "type": "postfix_transport_evidence_only", "recipient": RECIPIENT,
                "complete_transport_correlation": True,
                "entries": [{"case_id": f"case{i}", "run_id": rid, "queue_id": f"A1B2C{i}",
                             "state": "transport_sent_not_mailbox_verified"}
                            for i, rid in enumerate(ids)]}
        data.update(overrides)
        self.evidence.write_text(json.dumps(data))

    def message(self, rid, where=None, name="1", folder="new"):
        target = where or self.inbox
        (target / folder / name).write_bytes(
            f"From: sender@example.org\r\nTo: {RECIPIENT}\r\n"
            f"Message-ID: <{rid}@spamgate-qualification.invalid>\r\n"
            "Subject: test\r\n\r\nprivate body\r\n".encode())

    def call(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), "--transport-evidence", str(self.evidence),
                               "--inbox-maildir", str(self.inbox), "--junk-maildir", str(self.junk),
                               "--recipient", RECIPIENT, "--confirm-recipient", RECIPIENT,
                               "--output", str(self.output), *args], capture_output=True, text=True, timeout=8)

    def test_inbox_placement(self):
        self.message(RID1)
        r = self.call()
        self.assertEqual(r.returncode, 0, r.stderr)
        result = json.loads(self.output.read_text())
        self.assertEqual(result["counts"]["inbox"], 1)
        self.assertTrue(result["complete_maildir_correlation"])
        self.assertNotIn("private body", self.output.read_text())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_junk_placement_cur(self):
        self.message(RID1, self.junk, folder="cur")
        self.assertEqual(self.call().returncode, 0)
        self.assertEqual(json.loads(self.output.read_text())["counts"]["junk"], 1)

    def test_missing_is_incomplete(self):
        self.assertEqual(self.call().returncode, 3)
        self.assertEqual(json.loads(self.output.read_text())["counts"]["missing"], 1)

    def test_duplicate_across_folders_is_incomplete(self):
        self.message(RID1)
        self.message(RID1, self.junk)
        self.assertEqual(self.call().returncode, 3)
        self.assertEqual(json.loads(self.output.read_text())["counts"]["duplicate"], 1)

    def test_unrelated_message_is_ignored(self):
        self.message(RID2)
        self.assertEqual(self.call().returncode, 3)

    def test_two_cases_require_both(self):
        self.write_evidence([RID1, RID2])
        self.message(RID1)
        self.assertEqual(self.call().returncode, 3)
        self.assertEqual(json.loads(self.output.read_text())["counts"]["missing"], 1)

    def test_two_cases_complete(self):
        self.write_evidence([RID1, RID2])
        self.message(RID1)
        self.message(RID2, self.junk)
        self.assertEqual(self.call().returncode, 0)

    def test_expected_folder_passes(self):
        self.message(RID1, self.junk)
        expected = self.root / "expected.jsonl"
        expected.write_text(json.dumps({"case_id": "case0", "folder": "Junk"}) + "\n")
        result = self.call("--expected-placement", str(expected))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(self.output.read_text())["entries"][0]["placement_matches"])

    def test_wrong_expected_folder_fails(self):
        self.message(RID1)
        expected = self.root / "expected.jsonl"
        expected.write_text(json.dumps({"case_id": "case0", "folder": "Junk"}) + "\n")
        self.assertEqual(self.call("--expected-placement", str(expected)).returncode, 3)
        result = json.loads(self.output.read_text())
        self.assertEqual(result["placement_mismatches"], 1)
        self.assertFalse(result["complete_maildir_correlation"])

    def test_incomplete_expectations_refused(self):
        self.write_evidence([RID1, RID2])
        expected = self.root / "expected.jsonl"
        expected.write_text(json.dumps({"case_id": "case0", "folder": "INBOX"}) + "\n")
        self.assertEqual(self.call("--expected-placement", str(expected)).returncode, 2)
        self.assertFalse(self.output.exists())

    def test_duplicate_expectations_refused(self):
        expected = self.root / "expected.jsonl"
        row = json.dumps({"case_id": "case0", "folder": "INBOX"}) + "\n"
        expected.write_text(row + row)
        self.assertEqual(self.call("--expected-placement", str(expected)).returncode, 2)

    def test_reject_incomplete_transport_evidence(self):
        self.write_evidence([RID1], complete_transport_correlation=False)
        self.assertEqual(self.call().returncode, 2)
        self.assertFalse(self.output.exists())

    def test_reject_wrong_recipient(self):
        self.write_evidence([RID1], recipient="wrong@example.org")
        self.assertEqual(self.call().returncode, 2)

    def test_reject_duplicate_transport_ids(self):
        self.write_evidence([RID1, RID1])
        self.assertEqual(self.call().returncode, 2)

    def test_reject_duplicate_queue_ids(self):
        self.write_evidence([RID1, RID2])
        data = json.loads(self.evidence.read_text())
        data["entries"][1]["queue_id"] = data["entries"][0]["queue_id"]
        self.evidence.write_text(json.dumps(data))
        self.assertEqual(self.call().returncode, 2)

    def test_reject_symlinked_maildir_file(self):
        outside = self.root / "outside"
        outside.write_text("test")
        (self.inbox / "new" / "linked").symlink_to(outside)
        self.assertEqual(self.call().returncode, 2)
        self.assertFalse(self.output.exists())

    def test_reject_symlinked_maildir_folder(self):
        (self.inbox / "cur").rmdir()
        (self.inbox / "cur").symlink_to(self.root)
        self.assertEqual(self.call().returncode, 2)

    def test_reject_symlinked_transport_evidence(self):
        real = self.root / "real.json"
        self.evidence.rename(real)
        self.evidence.symlink_to(real)
        self.assertEqual(self.call().returncode, 2)

    def test_reject_existing_output(self):
        self.message(RID1)
        self.output.write_text("preserve")
        self.assertEqual(self.call().returncode, 2)
        self.assertEqual(self.output.read_text(), "preserve")

    def test_reject_oversized_headers(self):
        (self.inbox / "new" / "large").write_bytes(b"X-Test: " + b"x" * 140000 + b"\r\n\r\n")
        self.assertEqual(self.call().returncode, 2)
        self.assertFalse(self.output.exists())

    def test_reject_missing_maildir_subfolder(self):
        (self.junk / "cur").rmdir()
        self.assertEqual(self.call().returncode, 2)

    def test_reject_identical_maildir_paths(self):
        self.assertEqual(self.call("--junk-maildir", str(self.inbox)).returncode, 2)


if __name__ == "__main__":
    unittest.main()
