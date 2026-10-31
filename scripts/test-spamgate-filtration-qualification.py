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
                self.assertEqual([x['event'] for x in events], ['attempted', 'smtp_accepted'])
                self.assertEqual(len(server.messages), 1)
                self.assertIn(events[0]['run_id'].encode(), server.messages[0])
                self.assertIn(b'To: spambox@example.org', server.messages[0])
                self.assertNotIn(b'To: old@example.org', server.messages[0])
                observations = self.root / 'observations.jsonl'
                labels = self.root / 'labels.jsonl'
                observations.write_text('')
                missing = self.call('reconcile', '--report', str(report_path), '--observations', str(observations), '--labels-out', str(labels))
                self.assertEqual(missing.returncode, 2)
                self.assertFalse(labels.exists())
                observations.write_text(json.dumps({'run_id': events[0]['run_id'], 'action': 'accept'}) + '\n')
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
                observations.write_text(json.dumps({'run_id': events[0]['run_id'], 'action': 'reject'}) + '\n')
                labels = self.root / 'labels.jsonl'
                reconcile = self.call('reconcile', '--report', str(report_path), '--observations', str(observations), '--labels-out', str(labels))
                self.assertEqual(reconcile.returncode, 2)
                self.assertFalse(labels.exists())
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


if __name__ == '__main__':
    unittest.main()
