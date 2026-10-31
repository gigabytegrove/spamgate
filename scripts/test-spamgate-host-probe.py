import contextlib
import io
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).with_name("spamgate-host-probe.py")

class HostProbeTests(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              capture_output=True, text=True, timeout=15)

    def test_default_does_not_contact_smtp(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "preflight_only")
        self.assertFalse(report["smtp"]["attempted"])
        self.assertIn("launcher", report["preflight"])

    def test_send_requires_recipient_confirmation(self):
        result = self.invoke("--send", "--recipient", "test@example.org")
        self.assertEqual(result.returncode, 2)
        self.assertIn("matching", result.stderr)

    def test_rejects_header_injection(self):
        result = self.invoke("--send", "--recipient", "a@example.org",
                             "--confirm-recipient", "a@example.org",
                             "--sender", "a@example.org\r\nBcc:bad@example.org")
        self.assertEqual(result.returncode, 2)

    def test_rejects_marker_newline(self):
        result = self.invoke("--send", "--recipient", "a@example.org",
                             "--confirm-recipient", "a@example.org",
                             "--category-marker", "foo\nbar")
        self.assertEqual(result.returncode, 2)

    def test_remote_target_refused_by_default(self):
        result = self.invoke("--send", "--recipient", "a@example.org",
                             "--confirm-recipient", "a@example.org",
                             "--host", "192.0.2.1", "--sender", "probe@example.org")
        self.assertEqual(result.returncode, 2)
        self.assertIn("non-loopback", result.stderr)

    def test_sender_required_for_live_mail(self):
        result = self.invoke("--send", "--recipient", "a@example.org",
                             "--confirm-recipient", "a@example.org")
        self.assertEqual(result.returncode, 2)
        self.assertIn("explicit --sender", result.stderr)

    def test_hostname_refused_to_prevent_dns_rebinding(self):
        result = self.invoke("--send", "--recipient", "a@example.org",
                             "--confirm-recipient", "a@example.org",
                             "--sender", "probe@example.org",
                             "--host", "localhost")
        self.assertEqual(result.returncode, 2)
        self.assertIn("IP literal", result.stderr)

    def test_report_exclusive_create(self):
        with tempfile.TemporaryDirectory() as directory:
            target = str(pathlib.Path(directory) / "report.json")
            first = self.invoke("--output", target)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(pathlib.Path(target).stat().st_mode & 0o777, 0o600)
            second = self.invoke("--output", target)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(json.loads(pathlib.Path(target).read_text())["status"], "preflight_only")

    def test_invalid_port(self):
        self.assertEqual(self.invoke("--port", "0").returncode, 2)

    def test_no_implicit_smtp_with_marker(self):
        self.assertEqual(self.invoke("--category-marker", "SGTUBE").returncode, 2)

if __name__ == "__main__":
    unittest.main()
