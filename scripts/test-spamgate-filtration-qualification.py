"""Isolated native corpus qualification tests; never contacts the installed MTA."""
import json
import pathlib
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest

SCRIPT = pathlib.Path(__file__).with_name('spamgate-filtration-qualification.py')


class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        self.wfile.write(b'220 loopback test\r\n')
        data = False
        while True:
            line = self.rfile.readline(131073)
            if not line:
                return
            if data:
                if line == b'.\r\n':
                    data = False
                    self.server.messages.append(bytes(self.server.current))
                    self.wfile.write(b'250 2.0.0 accepted\r\n')
                else:
                    self.server.current.extend(line)
                continue
            command = line.decode('ascii', 'replace').upper()
            if command.startswith('EHLO '):
                self.wfile.write(b'250-loopback\r\n250 SIZE 131072\r\n')
            elif command.startswith('MAIL FROM:'):
                self.wfile.write(b'250 sender ok\r\n')
            elif command.startswith('RCPT TO:'):
                self.wfile.write(b'550 recipient refused\r\n' if self.server.reject else b'250 recipient ok\r\n')
            elif command.startswith('DATA'):
                self.server.current = bytearray()
                data = True
                self.wfile.write(b'354 send data\r\n')
            elif command.startswith('QUIT'):
                self.wfile.write(b'221 goodbye\r\n')
                return
            else:
                self.wfile.write(b'500 unexpected\r\n')
            self.wfile.flush()


class SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, reject=False):
        super().__init__(('127.0.0.1', 0), SMTPHandler)
        self.reject = reject
        self.messages = []
        self.current = bytearray()


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.manifest = self.root / 'manifest.jsonl'
        self.fixture = self.root / 'ham.eml'
        self.fixture.write_bytes(b'From: Test <test@example.org>\r\nTo: old@example.org\r\nSubject: Normal message\r\n\r\nHello world\r\n')
        self.manifest.write_text(json.dumps({'case_id': 'ham1', 'label': 'ham', 'cohort': 'direct', 'file': 'ham.eml'}) + '\n')

    def call(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, timeout=15)

    def send(self, port, output, *extra):
        return self.call('send', '--manifest', str(self.manifest), '--recipient', 'spambox@example.org',
                         '--confirm-recipient', 'spambox@example.org', '--sender', 'probe@example.org',
                         '--port', str(port), '--output', str(output), *extra)

    def test_plan_no_mail_and_counts(self):
        result = self.call('plan', '--manifest', str(self.manifest))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'validated_no_mail_sent')

    def test_rejects_duplicate_bytes_and_ids(self):
        (self.root / 'duplicate.eml').write_bytes(self.fixture.read_bytes())
        with self.manifest.open('a') as handle:
            handle.write(json.dumps({'case_id': 'ham2', 'label': 'spam', 'cohort': 'bulk', 'file': 'duplicate.eml'}) + '\n')
        result = self.call('plan', '--manifest', str(self.manifest))
        self.assertEqual(result.returncode, 2)
        self.assertIn('duplicate message bytes', result.stderr)

    def test_rejects_traversal_and_symlink(self):
        self.manifest.write_text(json.dumps({'case_id': 'bad', 'label': 'ham', 'cohort': 'direct', 'file': '../other.eml'}) + '\n')
        self.assertEqual(self.call('plan', '--manifest', str(self.manifest)).returncode, 2)
        (self.root / 'link.eml').symlink_to(self.fixture)
        self.manifest.write_text(json.dumps({'case_id': 'bad', 'label': 'ham', 'cohort': 'direct', 'file': 'link.eml'}) + '\n')
        self.assertEqual(self.call('plan', '--manifest', str(self.manifest)).returncode, 2)

    def test_requires_explicit_sender_and_confirmation(self):
        result = self.call('send', '--manifest', str(self.manifest), '--recipient', 'spambox@example.org',
                           '--output', str(self.root / 'report.jsonl'))
        self.assertEqual(result.returncode, 2)

    def test_refuses_non_ip_hostname(self):
        result = self.send(25, self.root / 'report.jsonl', '--host', 'localhost')
        self.assertEqual(result.returncode, 2)
        self.assertIn('IP literal', result.stderr)

    def test_accept_wire_and_reconcile_only_observed(self):
        with SMTPServer() as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                report_path = self.root / 'report.jsonl'
                result = self.send(server.server_address[1], report_path)
                self.assertEqual(result.returncode, 0, result.stderr)
                events = [json.loads(line) for line in report_path.read_text().splitlines()]
                self.assertEqual([x['event'] for x in events], ['plan', 'attempted', 'smtp_accepted'])
                self.assertEqual(len(server.messages), 1)
                self.assertIn(events[1]['run_id'].encode(), server.messages[0])
                self.assertIn(b'To: spambox@example.org', server.messages[0])
                self.assertNotIn(b'To: old@example.org', server.messages[0])
                observations = self.root / 'observations.jsonl'
                labels = self.root / 'labels.jsonl'
                observations.write_text('')
                missing = self.call('reconcile', '--report', str(report_path), '--observations', str(observations), '--labels-out', str(labels))
                self.assertEqual(missing.returncode, 2)
                self.assertFalse(labels.exists())
                observations.write_text(json.dumps({'run_id': events[1]['run_id'], 'action': 'accept'}) + '\n')
                valid = self.call('reconcile', '--report', str(report_path), '--observations', str(observations), '--labels-out', str(labels))
                self.assertEqual(valid.returncode, 0, valid.stderr)
                row = json.loads(labels.read_text().strip())
                self.assertEqual(row['label'], 'ham')
                self.assertEqual(row['action'], 'accept')
                self.assertEqual(len(row['id']), 64)
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_refusal_never_yields_evaluation_labels(self):
        with SMTPServer(reject=True) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                report_path = self.root / 'refused.jsonl'
                result = self.send(server.server_address[1], report_path)
                self.assertEqual(result.returncode, 3, result.stderr)
                events = [json.loads(line) for line in report_path.read_text().splitlines()]
                self.assertEqual(events[-1]['event'], 'failed')
                observations = self.root / 'observations.jsonl'
                observations.write_text(json.dumps({'run_id': events[1]['run_id'], 'action': 'reject'}) + '\n')
                labels = self.root / 'labels.jsonl'
                reconcile = self.call('reconcile', '--report', str(report_path), '--observations', str(observations), '--labels-out', str(labels))
                self.assertEqual(reconcile.returncode, 2)
                self.assertFalse(labels.exists())
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_partial_batch_cannot_be_misreported_as_complete(self):
        with SMTPServer() as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                report = self.root / 'partial.jsonl'
                result = self.send(server.server_address[1], report)
                self.assertEqual(result.returncode, 0, result.stderr)
                events = [json.loads(x) for x in report.read_text().splitlines()]
                events[0]['cases'] = 2  # interrupted before second attempt
                report.write_text('\n'.join(json.dumps(x) for x in events) + '\n')
                observed = self.root / 'observed.jsonl'
                observed.write_text(json.dumps({'run_id': events[1]['run_id'], 'action': 'accept'}) + '\n')
                labels = self.root / 'labels.jsonl'
                reconciled = self.call('reconcile', '--report', str(report), '--observations', str(observed), '--labels-out', str(labels))
                self.assertEqual(reconciled.returncode, 2)
                self.assertFalse(labels.exists())
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_extra_observation_is_rejected(self):
        with SMTPServer() as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                report = self.root / 'report.jsonl'
                self.assertEqual(self.send(server.server_address[1], report).returncode, 0)
                events = [json.loads(x) for x in report.read_text().splitlines()]
                observed = self.root / 'observed.jsonl'
                observed.write_text(json.dumps({'run_id': events[1]['run_id'], 'action': 'accept'}) + '\n' + json.dumps({'run_id': 'unknown', 'action': 'reject'}) + '\n')
                labels = self.root / 'labels.jsonl'
                self.assertEqual(self.call('reconcile', '--report', str(report), '--observations', str(observed), '--labels-out', str(labels)).returncode, 2)
                self.assertFalse(labels.exists())
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_reconcile_never_overwrites_existing_labels(self):
        with SMTPServer() as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                report = self.root / 'report.jsonl'
                self.assertEqual(self.send(server.server_address[1], report).returncode, 0)
                events = [json.loads(x) for x in report.read_text().splitlines()]
                observed = self.root / 'observed.jsonl'
                observed.write_text(json.dumps({'run_id': events[1]['run_id'], 'action': 'accept'}) + '\n')
                labels = self.root / 'labels.jsonl'
                labels.write_text('PRESERVE ORIGINAL')
                result = self.call('reconcile', '--report', str(report), '--observations', str(observed), '--labels-out', str(labels))
                self.assertEqual(result.returncode, 2)
                self.assertEqual(labels.read_text(), 'PRESERVE ORIGINAL')
                self.assertEqual(list(self.root.glob('.labels.jsonl.pending-*')), [])
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_output_exclusive(self):
        with SMTPServer() as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                report = self.root / 'existing.jsonl'
                report.write_text('DO NOT REPLACE')
                result = self.send(server.server_address[1], report)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(report.read_text(), 'DO NOT REPLACE')
                self.assertEqual(server.messages, [])
            finally:
                server.shutdown()
                thread.join(timeout=5)


    def synthetic_evidence(self):
        """Complete, offline-only journal and independent observation fixture."""
        run_id = 'a' * 32
        digest = 'b' * 64
        base = {'case_id': 'ham1', 'id': digest, 'label': 'ham',
                'cohort': 'direct', 'run_id': run_id}
        events = [{'event': 'plan', 'cases': 1},
                  {**base, 'event': 'attempted'},
                  {**base, 'event': 'smtp_accepted'}]
        report = self.root / 'synthetic-report.jsonl'
        observed = self.root / 'synthetic-observations.jsonl'
        labels = self.root / 'synthetic-labels.jsonl'
        observed.write_text(json.dumps({'run_id': run_id, 'action': 'accept'}) + '\n')
        return events, report, observed, labels

    def reconcile_evidence(self, events, report, observed, labels):
        report.write_text('\n'.join(json.dumps(event) for event in events) + '\n')
        return self.call('reconcile', '--report', str(report),
                         '--observations', str(observed), '--labels-out', str(labels))

    def test_offline_valid_reconciliation_control(self):
        events, report, observed, labels = self.synthetic_evidence()
        result = self.reconcile_evidence(events, report, observed, labels)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(labels.read_text())['id'], 'b' * 64)

    def test_duplicate_json_keys_refused_in_all_evidence_inputs(self):
        self.manifest.write_text(
            '{"case_id":"ham1","label":"ham","label":"spam","cohort":"direct","file":"ham.eml"}\n')
        result = self.call('plan', '--manifest', str(self.manifest))
        self.assertEqual(result.returncode, 2)
        self.assertIn('duplicate JSON object key', result.stderr)

        self.manifest.write_text(
            '{"case_id":"ham1","label":"ham","cohort":"direct","file":"ham.eml",'
            '"\\u006cabel":"spam"}\n')
        result = self.call('plan', '--manifest', str(self.manifest))
        self.assertEqual(result.returncode, 2)
        self.assertIn('duplicate JSON object key', result.stderr)

        events, report, observed, labels = self.synthetic_evidence()
        report.write_text('{"event":"plan","cases":1,"cases":2}\n'
                          + '\n'.join(json.dumps(e) for e in events[1:]) + '\n')
        result = self.call('reconcile', '--report', str(report),
                           '--observations', str(observed), '--labels-out', str(labels))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(labels.exists())

        events, report, observed, labels = self.synthetic_evidence()
        observed.write_text('{"run_id":"' + 'a' * 32
                            + '","action":"accept","action":"reject"}\n')
        result = self.reconcile_evidence(events, report, observed, labels)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(labels.exists())

    def test_contradictory_or_incomplete_terminal_evidence_refused(self):
        for name, mutate in (
            ('terminal before attempt', lambda e: [e[0], e[2], e[1]]),
            ('terminal label changed', lambda e: [e[0], e[1], {**e[2], 'label': 'spam'}]),
            ('terminal extra error', lambda e: [e[0], e[1], {**e[2], 'error': 'hidden'}]),
            ('missing attempted field', lambda e: [e[0], {k: v for k, v in e[1].items() if k != 'label'}, e[2]]),
            ('invalid run identity', lambda e: [e[0], {**e[1], 'run_id': 'bad'}, {**e[2], 'run_id': 'bad'}]),
            ('invalid digest', lambda e: [e[0], {**e[1], 'id': 'z' * 64}, {**e[2], 'id': 'z' * 64}]),
            ('unpaired attempt', lambda e: [e[0], e[1]]),
        ):
            with self.subTest(name=name):
                events, report, observed, labels = self.synthetic_evidence()
                result = self.reconcile_evidence(mutate(events), report, observed, labels)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(labels.exists())

    def test_malformed_observations_fail_cleanly_without_output(self):
        for raw in ('{"run_id":[],"action":"accept"}',
                    '{"run_id":null,"action":"accept"}',
                    '{"run_id":"' + 'a' * 32 + '","action":{}}',
                    '{"run_id":"' + 'a' * 32 + '","action":NaN}',
                    '{"run_id":"' + 'a' * 32 + '","action":"accept","extra":1}'):
            with self.subTest(raw=raw):
                events, report, observed, labels = self.synthetic_evidence()
                observed.write_text(raw + '\n')
                result = self.reconcile_evidence(events, report, observed, labels)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('Traceback', result.stderr)
                self.assertFalse(labels.exists())

    def test_manifest_wrong_file_type_and_excess_blank_lines_refused(self):
        self.manifest.write_text(
            '{"case_id":"ham1","label":"ham","cohort":"direct","file":42}\n')
        result = self.call('plan', '--manifest', str(self.manifest))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('Traceback', result.stderr)
        self.manifest.write_text('\n' * (4 * 1000 + 130))
        result = self.call('plan', '--manifest', str(self.manifest))
        self.assertEqual(result.returncode, 2)
        self.assertIn('physical line limit', result.stderr)
        self.manifest.write_bytes(b'{' + b'x' * (2 << 20))
        result = self.call('plan', '--manifest', str(self.manifest))
        self.assertEqual(result.returncode, 2)
        self.assertIn('exceeds 64 KiB', result.stderr)
        self.assertNotIn('Traceback', result.stderr)


    def test_non_object_plan_and_event_types_refused_without_traceback(self):
        for plan in ('[]', '[{"event":"plan","cases":1}]', 'null',
                     '{"event":"plan","cases":NaN}'):
            with self.subTest(plan=plan):
                events, report, observed, labels = self.synthetic_evidence()
                report.write_text(plan + '\n' + '\n'.join(json.dumps(e) for e in events[1:]) + '\n')
                result = self.call('reconcile', '--report', str(report),
                                   '--observations', str(observed), '--labels-out', str(labels))
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('Traceback', result.stderr)
                self.assertFalse(labels.exists())
        for bad in ([], {'event': []}, {'event': {}}, {'event': None}):
            with self.subTest(event=bad):
                events, report, observed, labels = self.synthetic_evidence()
                events[1] = bad
                result = self.reconcile_evidence(events, report, observed, labels)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('Traceback', result.stderr)
                self.assertFalse(labels.exists())

    def test_duplicate_message_digest_cannot_inflate_reconciled_corpus(self):
        events, report, observed, labels = self.synthetic_evidence()
        second = {**events[1], 'case_id': 'spam2', 'run_id': 'c' * 32,
                  'label': 'spam'}
        events[0]['cases'] = 2
        events.extend([second, {**second, 'event': 'smtp_accepted'}])
        observed.write_text(json.dumps({'run_id': 'a' * 32, 'action': 'accept'}) + '\n'
                            + json.dumps({'run_id': 'c' * 32, 'action': 'reject'}) + '\n')
        result = self.reconcile_evidence(events, report, observed, labels)
        self.assertEqual(result.returncode, 2)
        self.assertIn('duplicate case, run ID or message digest', result.stderr)
        self.assertFalse(labels.exists())


if __name__ == '__main__':
    unittest.main()
