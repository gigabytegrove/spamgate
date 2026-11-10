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

    def test_duplicate_fixture_digest_across_distinct_cases_refused(self):
        second = {"case_id": "other", "run_id": "c" * 32, "id": DIGEST,
                  "label": "spam", "cohort": "forwarded"}
        self.rows[0]["cases"] = 2
        self.rows.extend((dict(second, event="attempted"),
                          dict(second, event="smtp_accepted")))
        self.write_rows()
        self.assert_refused()

    def test_distinct_fixture_digests_remain_accepted_as_report_evidence(self):
        second = {"case_id": "other", "run_id": "c" * 32, "id": "d" * 64,
                  "label": "spam", "cohort": "forwarded"}
        self.rows[0]["cases"] = 2
        self.rows.extend((dict(second, event="attempted"),
                          dict(second, event="smtp_accepted")))
        self.write_rows()
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(len(evidence["entries"]), 2)
        self.assertFalse(evidence["complete_transport_correlation"])

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

    def write_transport(self, extra_recipient=None):
        lines = [
            f"Nov  9 05:00:00 host postfix/cleanup[100]: ABCDE12345: message-id=<{RUN}@spamgate-qualification.invalid>",
            f"Nov  9 05:00:01 host postfix/local[101]: ABCDE12345: to=<{RECIPIENT}>, relay=local, status=sent (delivered)",
        ]
        if extra_recipient is not None:
            lines.append(
                f"Nov  9 05:00:02 host postfix/local[101]: ABCDE12345: to=<{extra_recipient}>, relay=local, status=deferred (temporary failure)"
            )
        lines.append("Nov  9 05:00:03 host postfix/qmgr[102]: ABCDE12345: removed")
        self.log.write_text("\n".join(lines) + "\n")

    def test_single_recipient_transport_is_correlated_not_mailbox_certified(self):
        self.write_transport()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertTrue(evidence["complete_transport_correlation"])
        self.assertEqual(evidence["entries"][0]["state"], "transport_sent_not_mailbox_verified")

    def test_mixed_recipient_queue_cannot_certify_single_recipient(self):
        self.write_transport("other@example.org")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertFalse(evidence["complete_transport_correlation"])
        self.assertEqual(evidence["entries"][0]["state"], "ambiguous_queue_identity")

    def test_mixed_recipient_sent_cannot_certify_single_recipient(self):
        self.write_transport("other@example.org")
        self.log.write_text(self.log.read_text().replace("status=deferred", "status=sent"))
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["entries"][0]["state"], "ambiguous_queue_identity")

    def test_sent_then_deferred_does_not_qualify(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(-1, f"Nov  9 05:00:02 host postfix/local[101]: ABCDE12345: to=<{RECIPIENT}>, relay=local, status=deferred (retry)")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["entries"][0]["state"], "mixed_transport_status_unverified")
        self.assertFalse(evidence["complete_transport_correlation"])

    def test_deferred_then_sent_does_not_qualify_without_lifecycle_proof(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(1, f"Nov  9 05:00:00 host postfix/local[101]: ABCDE12345: to=<{RECIPIENT}>, relay=local, status=deferred (retry)")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["entries"][0]["state"], "mixed_transport_status_unverified")

    def test_unknown_status_before_sent_refused(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(1, f"Nov  9 05:00:00 host postfix/local[101]: ABCDE12345: to=<{RECIPIENT}>, relay=local, status=expired (unrecognized)")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_unknown_status_other_recipient_refused(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(-1, "Nov  9 05:00:02 host postfix/local[101]: ABCDE12345: to=<other@example.org>, relay=local, status=unknown")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_unknown_status_unrelated_queue_ignored(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(1, "Nov  9 05:00:00 host postfix/local[101]: OTHER12345: to=<other@example.org>, status=unknown")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sent_with_failure_dsn_is_not_qualified(self):
        self.write_transport()
        self.log.write_text(self.log.read_text().replace("status=sent", "dsn=5.1.1, status=sent"))
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_sent_with_success_dsn_preserves_transport_only_evidence(self):
        self.write_transport()
        self.log.write_text(self.log.read_text().replace("status=sent", "dsn=2.0.0, status=sent"))
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "transport_sent_not_mailbox_verified")

    def test_malformed_dsn_is_not_qualified(self):
        self.write_transport()
        self.log.write_text(self.log.read_text().replace("status=sent", "dsn=2.x.0, status=sent"))
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)

    def test_duplicate_dsn_fields_are_not_qualified(self):
        self.write_transport()
        self.log.write_text(self.log.read_text().replace("status=sent", "dsn=2.0.0, dsn=5.0.0, status=sent"))
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)

    def test_deferred_only_is_not_qualified(self):
        self.write_transport()
        self.log.write_text(self.log.read_text().replace("status=sent", "status=deferred"))
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["entries"][0]["state"], "deferred")

    def test_duplicate_sent_events_remain_unqualified(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(-1, lines[1])
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["entries"][0]["state"], "duplicate_transport_sent")

    def test_qmgr_two_recipients_refuses_incomplete_transport_logs(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(1, "Nov  9 05:00:00 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, size=500, nrcpt=2 (queue active)")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["entries"][0]["state"], "ambiguous_queue_identity")

    def test_qmgr_one_recipient_preserves_transport_correlation(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(1, "Nov  9 05:00:00 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, size=500, nrcpt=1 (queue active)")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_qmgr_zero_recipients_is_not_certified(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(1, "Nov  9 05:00:00 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, size=500, nrcpt=0 (queue active)")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)

    def test_qmgr_multirecipient_before_cleanup_refused(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, "Nov  9 04:59:59 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, size=500, nrcpt=2 (queue active)")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        evidence = json.loads(self.output.read_text())
        self.assertEqual(evidence["entries"][0]["state"], "ambiguous_queue_identity")

    def test_qmgr_conflicting_counts_before_cleanup_refused(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, "Nov  9 04:59:58 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, nrcpt=2")
        lines.insert(1, "Nov  9 04:59:59 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, nrcpt=1")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)

    def test_qmgr_single_recipient_before_cleanup_preserves_correlation(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, "Nov  9 04:59:59 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, nrcpt=1")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_transport_before_cleanup_refuses_queue_identity(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, f"Nov  9 04:59:59 host postfix/local[101]: ABCDE12345: to=<{RECIPIENT}>, relay=local, status=sent (prior lifecycle)")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_queue_removal_before_cleanup_refuses_identity(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, "Nov  9 04:59:59 host postfix/qmgr[102]: ABCDE12345: removed")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_hold_before_cleanup_refuses_identity(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, "Nov  9 04:59:59 host postfix/cleanup[100]: ABCDE12345: hold: policy")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_unrelated_queue_before_cleanup_does_not_block(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, "Nov  9 04:59:59 host postfix/qmgr[102]: OTHER12345: removed")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_foreign_cleanup_before_probe_refuses_reused_queue(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, "Nov  9 04:59:59 host postfix/cleanup[100]: ABCDE12345: message-id=<earlier@example.org>")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_foreign_cleanup_after_probe_refuses_reused_queue(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(-1, "Nov  9 05:00:02 host postfix/cleanup[100]: ABCDE12345: message-id=<later@example.org>")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_unrelated_foreign_cleanup_preserves_probe(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, "Nov  9 04:59:59 host postfix/cleanup[100]: OTHER12345: message-id=<earlier@example.org>")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_foreign_qualification_cleanup_before_probe_refuses_reuse(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, f"Nov  9 04:59:59 host postfix/cleanup[100]: ABCDE12345: message-id=<{ 'c' * 32 }@spamgate-qualification.invalid>")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_foreign_qualification_cleanup_after_probe_refuses_reuse(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(-1, f"Nov  9 05:00:02 host postfix/cleanup[100]: ABCDE12345: message-id=<{ 'c' * 32 }@spamgate-qualification.invalid>")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_foreign_qualification_cleanup_on_other_queue_is_safe(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, f"Nov  9 04:59:59 host postfix/cleanup[100]: OTHER12345: message-id=<{ 'c' * 32 }@spamgate-qualification.invalid>")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_empty_case_id_refused(self):
        for row in self.rows[1:]:
            row["case_id"] = ""
        self.write_rows()
        self.assert_refused()

    def test_control_character_case_id_refused(self):
        for row in self.rows[1:]:
            row["case_id"] = "clean\nforged"
        self.write_rows()
        self.assert_refused()

    def test_oversized_case_id_refused(self):
        for row in self.rows[1:]:
            row["case_id"] = "x" * 129
        self.write_rows()
        self.assert_refused()

    def test_unrecognized_label_refused(self):
        for row in self.rows[1:]:
            row["label"] = "unreviewed"
        self.write_rows()
        self.assert_refused()

    def test_empty_cohort_refused(self):
        for row in self.rows[1:]:
            row["cohort"] = ""
        self.write_rows()
        self.assert_refused()

    def test_unknown_cohort_refused(self):
        for row in self.rows[1:]:
            row["cohort"] = "unverified"
        self.write_rows()
        self.assert_refused()

    def test_case_id_with_unsupported_punctuation_refused(self):
        for row in self.rows[1:]:
            row["case_id"] = "clean:other"
        self.write_rows()
        self.assert_refused()

    def test_valid_nondefault_cohort_preserved(self):
        for row in self.rows[1:]:
            row["cohort"] = "forwarded"
        self.write_rows()
        self.write_transport()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_symlink_report_refused(self):
        original = self.root / "original.jsonl"
        self.report.rename(original)
        self.report.symlink_to(original)
        self.assert_refused()


    def test_transport_without_status_on_same_queue_refused(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(-1, "Nov  9 05:00:02 host postfix/local[101]: ABCDE12345: to=<other@example.org>, relay=local, dsn=4.4.1")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_two_status_fields_on_transport_refused(self):
        self.write_transport()
        self.log.write_text(self.log.read_text().replace(
            "status=sent", "status=sent, status=bounced"))
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_malformed_status_field_refused(self):
        self.write_transport()
        self.log.write_text(self.log.read_text().replace(
            "status=sent", "status=2.0.0"))
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_unrelated_transport_without_status_does_not_poison_probe(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(-1, "Nov  9 05:00:02 host postfix/local[101]: OTHER12345: to=<other@example.org>, relay=local")
        self.log.write_text("\n".join(lines) + "\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_qmgr_missing_recipient_count_refused(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(1, "Nov  9 05:00:00 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, size=500 (queue active)")
        self.log.write_text("\\n".join(lines) + "\\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(self.output.read_text())["entries"][0]["state"], "ambiguous_queue_identity")

    def test_qmgr_malformed_recipient_count_refused(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(1, "Nov  9 05:00:00 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, nrcpt=unknown")
        self.log.write_text("\\n".join(lines) + "\\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)

    def test_qmgr_duplicate_recipient_count_refused(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(1, "Nov  9 05:00:00 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, nrcpt=1, nrcpt=2")
        self.log.write_text("\\n".join(lines) + "\\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)

    def test_qmgr_missing_count_before_cleanup_refused(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(0, "Nov  9 04:59:59 host postfix/qmgr[102]: ABCDE12345: from=<sender@example.org>, size=500")
        self.log.write_text("\\n".join(lines) + "\\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 3, result.stderr)

    def test_qmgr_missing_count_on_unrelated_queue_isolated(self):
        self.write_transport()
        lines = self.log.read_text().splitlines()
        lines.insert(1, "Nov  9 05:00:00 host postfix/qmgr[102]: OTHER12345: from=<sender@example.org>, size=500")
        self.log.write_text("\\n".join(lines) + "\\n")
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
