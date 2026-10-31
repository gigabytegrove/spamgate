"""Integration tests: real SMTP wire exchange against an isolated loopback fake MTA.

No production Postfix/Dovecot is touched; these verify only the probe harness.
"""
import json
import pathlib
import socketserver
import subprocess
import sys
import threading
import unittest

SCRIPT = pathlib.Path(__file__).with_name("spamgate-host-probe.py")
RECIPIENT = "spambox@example.org"


class SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        self.wfile.write(b"220 localhost ESMTP test-harness\r\n")
        self.wfile.flush()
        in_data = False
        while True:
            line = self.rfile.readline(65537)
            if not line or len(line) > 65536:
                return
            if in_data:
                if line == b".\r\n":
                    in_data = False
                    if self.server.behavior == "reject_data":
                        self.wfile.write(b"554 5.7.1 synthetic refusal\r\n")
                    else:
                        self.server.messages.append(bytes(self.server.current))
                        self.wfile.write(b"250 2.0.0 queued as TEST123\r\n")
                    self.wfile.flush()
                else:
                    if len(self.server.current) + len(line) > 131072:
                        return
                    self.server.current.extend(line)
                continue
            cmd = line.decode("ascii", "replace").strip()
            upper = cmd.upper()
            if upper.startswith(("EHLO ", "HELO ")):
                self.wfile.write(b"250-localhost\r\n250-SIZE 131072\r\n250 8BITMIME\r\n")
            elif upper.startswith("MAIL FROM:"):
                self.wfile.write(b"250 2.1.0 sender ok\r\n")
            elif upper.startswith("RCPT TO:"):
                if self.server.behavior == "reject_rcpt":
                    self.wfile.write(b"550 5.1.1 recipient rejected\r\n")
                else:
                    self.wfile.write(b"250 2.1.5 recipient ok\r\n")
            elif upper == "DATA":
                self.server.current = bytearray()
                self.wfile.write(b"354 end with dot\r\n")
                in_data = True
            elif upper == "QUIT":
                self.wfile.write(b"221 2.0.0 bye\r\n")
                self.wfile.flush()
                return
            else:
                self.wfile.write(b"500 5.5.2 unsupported\r\n")
            self.wfile.flush()


class LoopbackSMTP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, behavior):
        super().__init__(("127.0.0.1", 0), SMTPHandler)
        self.behavior = behavior
        self.messages = []
        self.current = bytearray()


class SMTPWireTests(unittest.TestCase):
    def exercise(self, behavior, marker=None):
        with LoopbackSMTP(behavior) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                args = [sys.executable, str(SCRIPT), "--send",
                        "--recipient", RECIPIENT, "--confirm-recipient", RECIPIENT,
                        "--host", "127.0.0.1", "--port", str(server.server_address[1]),
                        "--timeout", "3", "--sender", "probe@example.org"]
                if marker:
                    args += ["--category-marker", marker]
                result = subprocess.run(args, text=True, capture_output=True, timeout=10)
                return result, json.loads(result.stdout), list(server.messages)
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_accept_and_correlatable_identifier(self):
        process, report, messages = self.exercise("accept")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(report["status"], "smtp_accepted")
        self.assertTrue(report["smtp"]["attempted"])
        self.assertEqual(len(messages), 1)
        self.assertIn(report["run_id"].encode(), messages[0])
        self.assertIn(b"X-SpamGate-Probe-ID:", messages[0])
        self.assertIn(b"Controlled mail delivery verification", messages[0])

    def test_rcpt_refusal_not_reported_as_success(self):
        process, report, messages = self.exercise("reject_rcpt")
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(report["status"], "smtp_failed")
        self.assertEqual(report["smtp"]["error_type"], "SMTPRecipientsRefused")
        self.assertEqual(messages, [])

    def test_data_refusal_not_reported_as_success(self):
        process, report, messages = self.exercise("reject_data")
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(report["status"], "smtp_failed")
        self.assertEqual(report["smtp"]["error_type"], "SMTPDataError")
        self.assertEqual(messages, [])

    def test_synthetic_marker_requires_explicit_opt_in(self):
        process, report, messages = self.exercise("accept", "SAFE-SYNTHETIC-TEST")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(len(messages), 1)
        self.assertIn(b"SAFE-SYNTHETIC-TEST", messages[0])
        self.assertIn(b"NOT real spam", messages[0])


if __name__ == "__main__":
    unittest.main()
