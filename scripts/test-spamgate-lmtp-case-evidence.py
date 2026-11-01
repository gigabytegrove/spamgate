"""Hermetic identity-level regressions for the disposable Postfix LMTP lab."""
import importlib.util
import json
import pathlib
import tempfile
import unittest

PATH = pathlib.Path(__file__).with_name('spamgate-lmtp-case-evidence.py')
SPEC = importlib.util.spec_from_file_location('spamgate_lmtp_cases', PATH)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class CaseEvidenceTests(unittest.TestCase):
    def fixture(self, delivered):
        cases = {}
        for index, (case, expected) in enumerate(lab.CASES.items()):
            cases[case] = {'INBOX': [], 'Junk': []}
            if delivered and expected:
                cases[case][expected] = [format(index + 1, '064x')]
        return {'schema': 1, 'scope': 'disposable_postfix_lmtp_case_identities',
                'cases': cases}

    def test_exact_five_deliveries_and_two_non_deliveries(self):
        result = lab.verify(self.fixture(False), self.fixture(True))
        self.assertEqual(result['verified_cases'], 7)
        self.assertEqual(result['new_delivered_identities'], 5)
        self.assertEqual(result['rejected_or_tempfailed_deliveries'], 0)

    def test_missing_wrong_box_and_unexpected_delivery_fail(self):
        before = self.fixture(False)
        for case, expected in lab.CASES.items():
            if expected:
                after = self.fixture(True)
                after['cases'][case][expected] = []
                with self.subTest(case=case), self.assertRaises(lab.EvidenceFailure):
                    lab.verify(before, after)
                after = self.fixture(True)
                value = after['cases'][case][expected].pop()
                after['cases'][case]['Junk' if expected == 'INBOX' else 'INBOX'].append(value)
                with self.assertRaises(lab.EvidenceFailure):
                    lab.verify(before, after)
            else:
                after = self.fixture(True)
                after['cases'][case]['INBOX'] = [format(999, '064x')]
                with self.assertRaises(lab.EvidenceFailure):
                    lab.verify(before, after)

    def test_missing_baseline_message_fails(self):
        with self.assertRaises(lab.EvidenceFailure):
            lab.verify(self.fixture(True), self.fixture(False))

    def test_duplicate_case_identity_fails(self):
        after = self.fixture(True)
        after['cases']['hold-request']['INBOX'] = after['cases']['legitimate']['INBOX'][:]
        with self.assertRaises(lab.EvidenceFailure):
            lab.verify(self.fixture(False), after)

    def test_schema_and_duplicate_fingerprints_fail(self):
        before, after = self.fixture(False), self.fixture(True)
        for mutation in ('extra', 'missing', 'duplicate', 'badsha', 'wrongtype'):
            value = json.loads(json.dumps(after))
            if mutation == 'extra':
                value['unexpected'] = True
            elif mutation == 'missing':
                del value['cases']['hold-request']
            elif mutation == 'duplicate':
                value['cases']['legitimate']['INBOX'] *= 2
            elif mutation == 'badsha':
                value['cases']['legitimate']['INBOX'] = ['unsafe']
            else:
                value['schema'] = True
            with self.subTest(mutation=mutation), self.assertRaises(lab.EvidenceFailure):
                lab.verify(before, value)

    def test_doveadm_query_is_fixed_and_private(self):
        commands = []
        def command(argv, **kwargs):
            commands.append((argv, kwargs))
            return b'a' * 32 + b' 7\n', b'', 0
        fingerprints = lab.query_uids('tag-to-junk', 'Junk', command)
        self.assertEqual(len(fingerprints), 1)
        self.assertEqual(commands[0][0][-3:],
                         ['HEADER', 'Message-ID', '<tag-to-junk@example.org>'])
        self.assertEqual(commands[0][1], {'timeout': 5, 'max_bytes': 16384})
        with self.assertRaises(lab.EvidenceFailure):
            lab.query_uids('tag-to-junk\r\n', 'Junk', command)

    def test_doveadm_malformed_and_duplicate_rejected(self):
        for data in (b'bad\n', b'\xff', b'a' * 32 + b' 0\n',
                     (b'a' * 32 + b' 1\n') * 2):
            with self.subTest(data=data[:8]), self.assertRaises(lab.EvidenceFailure):
                lab.query_uids('legitimate', 'INBOX',
                               lambda *a, **kw: (data, b'', 0))

    def test_disposable_guards(self):
        env = {'CI': 'true', 'GITHUB_ACTIONS': 'true',
               'SPAMGATE_DISPOSABLE_POSTFIX_LMTP_LAB': '1'}
        lab.require_disposable(lab.CONFIRM, env)
        for key in env:
            missing = dict(env)
            del missing[key]
            with self.assertRaises(lab.EvidenceFailure):
                lab.require_disposable(lab.CONFIRM, missing)

    def test_snapshot_rejects_symlinks_duplicates_and_nonfinite(self):
        with tempfile.TemporaryDirectory() as root:
            file = pathlib.Path(root) / 'evidence.json'
            file.write_text(json.dumps(self.fixture(False)))
            self.assertEqual(lab.read_snapshot(file)['schema'], 1)
            alias = pathlib.Path(root) / 'alias'
            alias.symlink_to(file)
            with self.assertRaises(lab.EvidenceFailure):
                lab.read_snapshot(alias)
            for data in (b'{"schema":1,"schema":2}', b'{"value":NaN}',
                         b'x' * (lab.MAX_BYTES + 1)):
                file.write_bytes(data)
                with self.assertRaises(lab.EvidenceFailure):
                    lab.read_snapshot(file)


if __name__ == '__main__':
    unittest.main()
