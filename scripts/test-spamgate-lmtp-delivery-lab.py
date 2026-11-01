"""Hermetic active-LMTP qualification regressions; never send real mail."""
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock

PATH = pathlib.Path(__file__).with_name("spamgate-lmtp-delivery-lab.py")
SPEC = importlib.util.spec_from_file_location("spamgate_lmtp_delivery_lab", PATH)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class LabTests(unittest.TestCase):
    def setUp(self):
        self.env = {"CI": "true", "GITHUB_ACTIONS": "true", "SPAMGATE_DISPOSABLE_LMTP_LAB": "1"}
        self.ids = [format(i, "032x") for i in range(1, len(lab.CASES) + 1)]

    def test_requires_three_guards_and_confirmation(self):
        for key in self.env:
            env = dict(self.env)
            env.pop(key)
            with self.assertRaises(lab.LabFailure):
                lab.assert_disposable(lab.CONFIRM, env)
        with self.assertRaises(lab.LabFailure):
            lab.assert_disposable("wrong", self.env)

    def test_missing_socket_is_refused(self):
        with mock.patch.object(lab.os.path, "exists", return_value=False):
            with self.assertRaisesRegex(lab.LabFailure, "socket unavailable"):
                lab.assert_disposable(lab.CONFIRM, self.env)

    def test_regular_file_is_refused(self):
        with tempfile.NamedTemporaryFile() as f:
            with mock.patch.object(lab, "SOCKET", f.name):
                with self.assertRaisesRegex(lab.LabFailure, "not a Unix socket"):
                    lab.assert_disposable(lab.CONFIRM, self.env)

    def test_message_has_expected_trusted_header_pair(self):
        for name, action, include_id, _ in lab.CASES:
            msg = lab.message(name, action, include_id, self.ids[0])
            self.assertEqual(msg["X-SpamGate-Action"], action)
            self.assertEqual(msg["X-SpamGate-ID"], self.ids[0] if include_id else None)
            self.assertEqual(msg["To"], lab.RECIPIENT)
            self.assertIn("Message-ID", msg)

    def test_doveadm_search_is_bounded_and_parsed(self):
        captured = []
        def command(args, **kwargs):
            captured.append((args, kwargs))
            return (b"a" * 32 + b" 123\n", b"", 0)
        mid = "<" + self.ids[0] + "@spamgate-lmtp-lab.invalid>"
        self.assertEqual(lab.search_mailbox("Junk", mid, command=command), 1)
        self.assertEqual(captured[0][0][:3], ["/usr/bin/doveadm", "search", "-u"])
        self.assertEqual(captured[0][1]["max_bytes"], 16384)

    def test_doveadm_rejects_unexpected_output(self):
        mid = "<" + self.ids[0] + "@spamgate-lmtp-lab.invalid>"
        for stdout, stderr, code in ((b"bad\n", b"", 0), (b"", b"secret", 0),
                                     (b"", b"", 1), (b"a" * 32 + b" 1\n" * 3, b"", 0)):
            with self.subTest(code=code):
                with self.assertRaises(lab.LabFailure):
                    lab.search_mailbox("INBOX", mid, command=lambda *a, **kw: (stdout, stderr, code))

    def test_doveadm_rejects_query_injection(self):
        with self.assertRaises(lab.LabFailure):
            lab.search_mailbox("../../Junk", "<" + self.ids[0] + "@spamgate-lmtp-lab.invalid>")
        with self.assertRaises(lab.LabFailure):
            lab.search_mailbox("INBOX", "evil\nmessage")

    def test_send_lmtp_refusal_fails_closed(self):
        class Fake:
            def __init__(self, socket, timeout): pass
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def sendmail(self, *args): return {lab.RECIPIENT: (550, b"private")}
        with self.assertRaisesRegex(lab.LabFailure, "refused"):
            lab.send_lmtp(lab.message(*lab.CASES[0][:3], self.ids[0]), factory=Fake)

    def test_polling_success_and_duplicate_detection(self):
        calls = iter([{"INBOX": 0, "Junk": 0}, {"INBOX": 1, "Junk": 0},
                      {"INBOX": 1, "Junk": 0}])
        self.assertEqual(lab.await_placement("id", "INBOX", query=lambda _: next(calls),
                                             sleep=lambda _: None), {"INBOX": 1, "Junk": 0})
        with self.assertRaisesRegex(lab.LabFailure, "duplicate"):
            lab.await_placement("id", "INBOX", query=lambda _: {"INBOX": 1, "Junk": 1})
        with self.assertRaisesRegex(lab.LabFailure, "wrong mailbox"):
            lab.await_placement("id", "INBOX", query=lambda _: {"INBOX": 0, "Junk": 1})

    def test_full_case_matrix_with_fake_delivery(self):
        stored = {}
        def query(mid):
            folder = stored.get(mid)
            return {"INBOX": int(folder == "INBOX"), "Junk": int(folder == "Junk")}
        def send(msg):
            case = str(msg["Subject"]).split()[-1]
            stored[str(msg["Message-ID"])] = next(item[3] for item in lab.CASES if item[0] == case)
        with mock.patch.object(lab, "assert_disposable"):
            result = lab.execute(confirm=lab.CONFIRM, env=self.env, ids=self.ids, send=send, query=query)
        self.assertEqual(result["verified_cases"], 5)
        self.assertTrue(result["ok"])
        self.assertEqual(len(stored), 5)
        self.assertNotIn("spamgatebeta@localhost", json.dumps(result))

    def test_preexisting_identifier_fails_before_sending(self):
        sent = []
        with mock.patch.object(lab, "assert_disposable"):
            with self.assertRaisesRegex(lab.LabFailure, "already exists"):
                lab.execute(confirm=lab.CONFIRM, env=self.env, ids=self.ids,
                            send=lambda msg: sent.append(msg),
                            query=lambda _: {"INBOX": 1, "Junk": 0})
        self.assertEqual(sent, [])

    def test_duplicate_ids_fail_before_sending(self):
        with mock.patch.object(lab, "assert_disposable"):
            with self.assertRaisesRegex(lab.LabFailure, "duplicate"):
                lab.execute(confirm=lab.CONFIRM, env=self.env, ids=[self.ids[0]] * 5,
                            send=lambda _: self.fail("sent"))


if __name__ == "__main__":
    unittest.main()
