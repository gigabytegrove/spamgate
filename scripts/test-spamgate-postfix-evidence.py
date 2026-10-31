"""Isolated Postfix transport evidence regressions; no live MTA access."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("spamgate-postfix-evidence.py")
RID1 = "a" * 32
RID2 = "b" * 32
DIGEST = "c" * 64
RECIPIENT = "test@example.org"


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.report = self.root / "report.jsonl"
        self.log = self.root / "mail.log"
        self.output = self.root / "evidence.json"
        self.write_report([(RID1, "ham1")])

    def write_report(self, cases):
        rows = [{"event": "plan", "cases": len(cases)}]
        for rid, cid in cases:
            base = {"case_id": cid, "run_id": rid, "id": DIGEST, "label": "ham", "cohort": "direct"}
            rows += [{**base, "event": "attempted"}, {**base, "event": "smtp_accepted"}]
        self.report.write_text("\n".join(json.dumps(x) for x in rows) + "\n")

    def call(self, *extra):
        return subprocess.run([sys.executable, str(SCRIPT), "--report", str(self.report),
                               "--postfix-log", str(self.log), "--recipient", RECIPIENT,
                               "--confirm-recipient", RECIPIENT, "--output", str(self.output), *extra],
                              text=True, capture_output=True, timeout=10)

    def test_transport_sent_does_not_claim_mailbox_delivery(self):
        self.log.write_text(f"Oct 31 09:00:00 mail postfix/cleanup[123]: A1B2C3: message-id=<{RID1}@spamgate-qualification.invalid>\n"
                            f"Oct 31 09:00:01 mail postfix/lmtp[124]: A1B2C3: to=<{RECIPIENT}>, relay=unix:private/dovecot-lmtp, status=sent (250 2.0.0 saved)\n"
                            "Oct 31 09:00:02 mail postfix/qmgr[125]: A1B2C3: removed\n")
        result = self.call()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertTrue(evidence["complete_transport_correlation"])
        self.assertEqual(evidence["entries"][0]["state"], "transport_sent_not_mailbox_verified")
        self.assertNotIn("delivered", json.dumps(evidence))
        self.assertTrue(evidence["entries"][0]["queue_removed"])

    def test_missing_cleanup_is_not_inferred_from_status(self):
        self.log.write_text(f"postfix/lmtp[124]: A1B2C3: to=<{RECIPIENT}>, status=sent\n")
        self.assertEqual(self.call().returncode, 3)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "no_cleanup_correlation")

    def test_wrong_recipient_is_not_a_match(self):
        self.log.write_text(f"postfix/cleanup[123]: A1B2C3: message-id=<{RID1}@spamgate-qualification.invalid>\n"
                            "postfix/lmtp[124]: A1B2C3: to=<other@example.org>, status=sent\n")
        self.assertEqual(self.call().returncode, 3)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "no_matching_recipient_transport")

    def test_deferred_then_sent_tracks_both_without_delivery_claim(self):
        self.log.write_text(f"postfix/cleanup[123]: A1B2C3: message-id=<{RID1}@spamgate-qualification.invalid>\n"
                            f"postfix/smtp[124]: A1B2C3: to=<{RECIPIENT}>, status=deferred\n"
                            f"postfix/lmtp[124]: A1B2C3: to=<{RECIPIENT}>, status=sent\n"
                            "postfix/qmgr[125]: A1B2C3: removed\n")
        self.assertEqual(self.call().returncode, 0)
        self.assertEqual(len(json.loads(self.output.read_text())["entries"][0]["transport_events"]), 2)

    def test_bounce_fails_even_if_sent(self):
        self.log.write_text(f"postfix/cleanup[123]: A1B2C3: message-id=<{RID1}@spamgate-qualification.invalid>\n"
                            f"postfix/lmtp[124]: A1B2C3: to=<{RECIPIENT}>, status=sent\n"
                            f"postfix/error[124]: A1B2C3: to=<{RECIPIENT}>, status=bounced\n")
        self.assertEqual(self.call().returncode, 3)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "bounced")

    def test_queue_identity_collision_is_ambiguous(self):
        self.write_report([(RID1, "ham1"), (RID2, "ham2")])
        self.log.write_text(f"postfix/cleanup[123]: A1B2C3: message-id=<{RID1}@spamgate-qualification.invalid>\n"
                            f"postfix/cleanup[123]: A1B2C3: message-id=<{RID2}@spamgate-qualification.invalid>\n"
                            f"postfix/lmtp[124]: A1B2C3: to=<{RECIPIENT}>, status=sent\n")
        self.assertEqual(self.call().returncode, 3)
        evidence = json.loads(self.output.read_text())
        self.assertTrue(all(x["state"] == "ambiguous_queue_identity" for x in evidence["entries"]))

    def test_duplicate_queue_for_one_run_is_ambiguous(self):
        self.log.write_text(f"postfix/cleanup[123]: A1B2C3: message-id=<{RID1}@spamgate-qualification.invalid>\n"
                            f"postfix/cleanup[123]: D4E5F6: message-id=<{RID1}@spamgate-qualification.invalid>\n")
        self.assertEqual(self.call().returncode, 3)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_queue_reuse_with_unrelated_message_id_is_ambiguous(self):
        self.log.write_text(f"postfix/cleanup[123]: A1B2C3: message-id=<{RID1}@spamgate-qualification.invalid>\n"
                            "postfix/qmgr[125]: A1B2C3: removed\n"
                            "postfix/cleanup[123]: A1B2C3: message-id=<unrelated@example.org>\n"
                            f"postfix/lmtp[124]: A1B2C3: to=<{RECIPIENT}>, status=sent\n")
        self.assertEqual(self.call().returncode, 3)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_sent_without_queue_removal_not_complete(self):
        self.log.write_text(f"postfix/cleanup[123]: A1B2C3: message-id=<{RID1}@spamgate-qualification.invalid>\n"
                            f"postfix/lmtp[124]: A1B2C3: to=<{RECIPIENT}>, status=sent\n")
        self.assertEqual(self.call().returncode, 3)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "sent_but_queue_removal_unobserved")

    def test_incomplete_report_is_refused(self):
        self.report.write_text(json.dumps({"event": "plan", "cases": 1}) + "\n")
        self.log.write_text("")
        self.assertEqual(self.call().returncode, 2)
        self.assertFalse(self.output.exists())

    def test_output_is_exclusive(self):
        self.log.write_text("")
        self.output.write_text("PRESERVE")
        self.assertEqual(self.call().returncode, 2)
        self.assertEqual(self.output.read_text(), "PRESERVE")

    def test_symlink_log_refused(self):
        real = self.root / "real.log"
        real.write_text("")
        self.log.symlink_to(real)
        self.assertEqual(self.call().returncode, 2)
        self.assertFalse(self.output.exists())

    def test_rotated_log_order(self):
        old = self.root / "mail.log.1"
        old.write_text(f"postfix/cleanup[123]: A1B2C3: message-id=<{RID1}@spamgate-qualification.invalid>\n")
        self.log.write_text(f"postfix/lmtp[124]: A1B2C3: to=<{RECIPIENT}>, status=sent\n"
                            "postfix/qmgr[125]: A1B2C3: removed\n")
        result = self.call("--postfix-log", str(old))
        self.assertEqual(result.returncode, 3)
        self.output.unlink()
        result = subprocess.run([sys.executable, str(SCRIPT), "--report", str(self.report),
                                 "--postfix-log", str(old), "--postfix-log", str(self.log),
                                 "--recipient", RECIPIENT, "--confirm-recipient", RECIPIENT,
                                 "--output", str(self.output)], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
