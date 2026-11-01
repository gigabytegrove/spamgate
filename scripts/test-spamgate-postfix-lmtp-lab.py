"""Hermetic regressions for the disposable Postfix/Milter/Dovecot LMTP gate."""
import importlib.util
import json
import pathlib
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

PATH = pathlib.Path(__file__).with_name("spamgate-postfix-lmtp-lab.py")
SPEC = importlib.util.spec_from_file_location("postfix_lmtp_lab", PATH)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.env = {"CI": "true", "GITHUB_ACTIONS": "true",
                    "SPAMGATE_DISPOSABLE_POSTFIX_LMTP_LAB": "1"}
        self.uid = 1234
        self.metadata = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=self.uid)

    def command(self, args, **kwargs):
        self.assertEqual(kwargs, {"timeout": 5, "max_bytes": 16384})
        if args[:2] == ["/usr/sbin/postconf", "-h"]:
            return (lab.EXPECTED[args[2]].encode() + b"\n", b"", 0)
        if args[:2] == ["/usr/bin/doveadm", "search"]:
            folder = args[5]
            self.assertIn(folder, ("INBOX", "Junk"))
            return (b"a" * 32 + b" 1\n", b"", 0)
        self.fail("unexpected command")

    def test_requires_all_disposable_guards(self):
        lab.require_disposable(lab.CONFIRM, self.env)
        for key in self.env:
            env = dict(self.env)
            del env[key]
            with self.assertRaises(lab.QualificationFailure):
                lab.require_disposable(lab.CONFIRM, env)
        with self.assertRaises(lab.QualificationFailure):
            lab.require_disposable("incorrect", self.env)

    def test_exact_route_and_socket_required(self):
        lab.verify_route(command=self.command, lstat=lambda _: self.metadata,
                         postfix_uid=self.uid)
        for bad in (stat.S_IFREG | 0o600, stat.S_IFSOCK | 0o666,
                    stat.S_IFSOCK | 0o660):
            with self.subTest(mode=bad):
                with self.assertRaises(lab.QualificationFailure):
                    lab.verify_route(command=self.command,
                                     lstat=lambda _: SimpleNamespace(st_mode=bad, st_uid=self.uid),
                                     postfix_uid=self.uid)
        with self.assertRaises(lab.QualificationFailure):
            lab.verify_route(command=self.command, lstat=lambda _: self.metadata,
                             postfix_uid=42)

    def test_milter_or_transport_drift_refused(self):
        for key in lab.EXPECTED:
            def wrong(args, **kwargs):
                if args[-1] == key:
                    return b"unsafe\n", b"", 0
                return self.command(args, **kwargs)
            with self.subTest(key=key), self.assertRaises(lab.QualificationFailure):
                lab.verify_route(command=wrong, lstat=lambda _: self.metadata,
                                 postfix_uid=self.uid)

    def test_command_errors_are_private(self):
        for answer in ((b"", b"secret", 0), (b"", b"", 1), (b"\xff", b"", 0)):
            with self.assertRaises(lab.QualificationFailure) as caught:
                lab.run(["fixed"], command=lambda *a, **kw: answer)
            self.assertNotIn("secret", str(caught.exception))

    def test_snapshot_contains_only_opaque_mailbox_fingerprints(self):
        result = lab.snapshot(command=self.command, lstat=lambda _: self.metadata,
                              postfix_uid=self.uid)
        self.assertEqual(len(result["mailboxes"]["INBOX"]), 1)
        self.assertRegex(result["mailboxes"]["Junk"][0], r"^[a-f0-9]{64}$")
        self.assertNotIn("spamgatebeta", json.dumps(result))
        self.assertNotEqual(result["mailboxes"]["INBOX"], result["mailboxes"]["Junk"])

    def test_malformed_doveadm_inventory_refused(self):
        for raw in (b"bad\n", b"a" * 32 + b" 0\n", b"a" * 32 + b" 1\n" * 3,
                    b"\xff", b"a" * 32 + b" 1\n" + b"a" * 32 + b" 1\n"):
            with self.subTest(raw=raw[:8]), self.assertRaises(lab.QualificationFailure):
                lab.mailbox_fingerprints("Junk",
                    command=lambda *a, **kw: (raw, b"", 0))
        with self.assertRaises(lab.QualificationFailure):
            lab.mailbox_fingerprints("../../etc")

    def evidence(self, inbox, junk):
        def hashes(prefix, count):
            return [format(i + prefix, "064x") for i in range(count)]
        return {"schema": 1, "scope": "disposable_postfix_milter_dovecot_lmtp",
                "route_verified": True, "mailboxes": {
                    "INBOX": hashes(1, inbox), "Junk": hashes(1000, junk)}}

    def test_expected_four_inbox_one_junk(self):
        before = self.evidence(2, 1)
        after = self.evidence(6, 2)
        result = lab.verify_delta(before, after)
        self.assertEqual((result["new_inbox"], result["new_junk"]), (4, 1))
        self.assertNotIn("mailboxes", result)

    def test_missing_duplicate_or_extra_mail_is_rejected(self):
        before = self.evidence(2, 1)
        cases = [self.evidence(5, 2), self.evidence(7, 2), self.evidence(6, 1),
                 self.evidence(6, 3), self.evidence(6, 2)]
        cases[-1]["mailboxes"]["INBOX"].remove(before["mailboxes"]["INBOX"][0])
        for after in cases:
            with self.subTest(after=after), self.assertRaises(lab.QualificationFailure):
                lab.verify_delta(before, after)

    def test_invalid_schema_and_duplicate_fingerprints_refused(self):
        before, after = self.evidence(1, 1), self.evidence(5, 2)
        for bad in (
            {"schema": 2, **{k: v for k, v in before.items() if k != "schema"}},
            {**before, "route_verified": False},
            {**before, "mailboxes": {"INBOX": ["invalid"], "Junk": []}},
            {**before, "mailboxes": {"INBOX": [before["mailboxes"]["INBOX"][0]] * 2,
                                   "Junk": []}},
        ):
            with self.assertRaises(lab.QualificationFailure):
                lab.verify_delta(bad, after)

    def test_snapshot_read_is_bounded_and_symlink_safe(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "before.json"
            path.write_text(json.dumps(self.evidence(1, 1)))
            self.assertEqual(lab.read_snapshot(path)["schema"], 1)
            alias = pathlib.Path(root) / "alias.json"
            alias.symlink_to(path)
            with self.assertRaises(lab.QualificationFailure):
                lab.read_snapshot(alias)
            path.write_bytes(b"x" * (lab.MAX_EVIDENCE_BYTES + 1))
            with self.assertRaises(lab.QualificationFailure):
                lab.read_snapshot(path)


if __name__ == "__main__":
    unittest.main()
