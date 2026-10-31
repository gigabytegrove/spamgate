"""Read-only loopback service probes: real sockets, no Postfix or SpamGate changes."""
import http.server
import json
import pathlib
import socket
import socketserver
import subprocess
import sys
import threading
import unittest

SCRIPT = pathlib.Path(__file__).with_name("spamgate-host-probe.py")


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/healthz":
            self.send_error(404)
            return
        self.send_response(self.server.response_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.server.response_body)))
        self.end_headers()
        try:
            self.wfile.write(self.server.response_body)
        except BrokenPipeError:
            pass

    def log_message(self, *args):
        pass


class MilterListener(socketserver.BaseRequestHandler):
    def handle(self):
        # A TCP connection is enough: no Milter handshake or SMTP command.
        self.request.settimeout(0.25)
        try:
            self.request.recv(1)
        except (OSError, TimeoutError):
            pass


class LoopbackServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ServiceProbeTests(unittest.TestCase):
    def exercise(self, *, health_status=200, body=b'{"status":"ok","version":"0.6.0-beta.2"}',
                 expected=None, milter_open=True, send=False):
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler) as health:
            health.response_status = health_status
            health.response_body = body
            with LoopbackServer(("127.0.0.1", 0), MilterListener) as milter:
                threads = []
                for server in (health, milter):
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    threads.append(thread)
                try:
                    args = [sys.executable, str(SCRIPT), "--check-services",
                            "--health-port", str(health.server_port),
                            "--milter-port", str(milter.server_address[1]),
                            "--timeout", "2"]
                    if expected:
                        args.extend(("--expect-version", expected))
                    if send:
                        args.extend(("--send", "--sender", "probe@example.org",
                                     "--recipient", "spambox@example.org",
                                     "--confirm-recipient", "spambox@example.org"))
                    if not milter_open:
                        milter.shutdown()
                        milter.server_close()
                        threads[1].join(timeout=3)
                    process = subprocess.run(args, text=True, capture_output=True, timeout=8)
                    return process, json.loads(process.stdout)
                finally:
                    health.shutdown()
                    threads[0].join(timeout=3)
                    if milter_open:
                        milter.shutdown()
                        threads[1].join(timeout=3)

    def test_healthy_loopback_services(self):
        process, report = self.exercise(expected="0.6.0-beta.2")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(report["status"], "preflight_only")
        self.assertTrue(report["services"]["ok"])
        self.assertEqual(report["services"]["health"]["version"], "0.6.0-beta.2")
        self.assertEqual(report["services"]["milter"]["status"], "tcp_listening")
        self.assertFalse(report["services"]["milter"]["protocol_verified"])
        self.assertFalse(report["smtp"]["attempted"])

    def test_non_200_health_refused(self):
        process, report = self.exercise(health_status=503)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["status"], "service_probe_failed")
        self.assertEqual(report["services"]["health"]["http_status"], 503)

    def test_redirect_is_not_followed(self):
        process, report = self.exercise(health_status=302)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["services"]["health"]["http_status"], 302)

    def test_malformed_health_json_refused(self):
        process, report = self.exercise(body=b"not-json")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["services"]["health"]["status"], "failed")

    def test_oversized_health_response_refused(self):
        process, report = self.exercise(body=b"x" * 4097)
        self.assertEqual(process.returncode, 1)
        self.assertIn("4096-byte", report["services"]["health"]["error"])

    def test_version_mismatch_refused(self):
        process, report = self.exercise(expected="0.6.0-beta.3")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["services"]["health"]["version"], "0.6.0-beta.2")
        self.assertFalse(report["services"]["ok"])

    def test_closed_milter_refused(self):
        process, report = self.exercise(milter_open=False)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["services"]["milter"]["status"], "failed")

    def test_unhealthy_services_prevent_opted_in_mail(self):
        process, report = self.exercise(health_status=503, send=True)
        self.assertEqual(process.returncode, 1)
        self.assertTrue(report["send_requested"])
        self.assertFalse(report["smtp"]["attempted"])

    def test_invalid_expect_version_requires_opt_in(self):
        process = subprocess.run([sys.executable, str(SCRIPT), "--expect-version", "0.6.0"],
                                 text=True, capture_output=True, timeout=8)
        self.assertEqual(process.returncode, 2)

    def test_invalid_service_port_refused(self):
        process = subprocess.run([sys.executable, str(SCRIPT), "--check-services",
                                  "--milter-port", "0"], text=True,
                                 capture_output=True, timeout=8)
        self.assertEqual(process.returncode, 2)


if __name__ == "__main__":
    unittest.main()
