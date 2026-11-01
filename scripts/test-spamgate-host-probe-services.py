"""Read-only loopback service probes: real sockets, no Postfix or SpamGate changes."""
import http.server
import json
import struct
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
        self.send_header("Content-Type", self.server.content_type)
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
        self.request.settimeout(1)
        try:
            if hasattr(self.server, "protocol_reply"):
                received = bytearray()
                while len(received) < 17:
                    chunk = self.request.recv(17 - len(received))
                    if not chunk:
                        break
                    received.extend(chunk)
                self.server.last_request = bytes(received)
                self.request.sendall(self.server.protocol_reply)
            else:
                self.request.recv(1)
        except (OSError, TimeoutError):
            pass


class LoopbackServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ServiceProbeTests(unittest.TestCase):
    def exercise(self, *, health_status=200, body=b'{"status":"ok","version":"0.6.0-beta.2"}',
                 expected=None, milter_open=True, send=False, content_type="application/json",
                 protocol=False, milter_reply=None, required_actions=None):
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler) as health:
            health.response_status = health_status
            health.response_body = body
            health.content_type = content_type
            with LoopbackServer(("127.0.0.1", 0), MilterListener) as milter:
                if protocol:
                    milter.protocol_reply = (milter_reply if milter_reply is not None else
                        struct.pack("!I", 13) + b"O" + struct.pack("!III", 6, 0x31, 0))
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
                    if protocol:
                        args.append("--verify-milter-protocol")
                    if required_actions:
                        args.extend(("--require-milter-actions", required_actions))
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

    def test_opt_in_milter_protocol_negotiation(self):
        process, report = self.exercise(protocol=True, required_actions="add_header,change_header,quarantine")
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(report["services"]["milter"]["status"], "protocol_verified")
        self.assertTrue(report["services"]["milter"]["protocol_verified"])
        self.assertEqual(report["services"]["milter"]["negotiated_version"], 6)
        self.assertTrue(report["services"]["milter"]["negotiated_actions"]["quarantine"])
        self.assertFalse(report["smtp"]["attempted"])

    def test_opt_in_milter_protocol_refuses_tcp_only_listener(self):
        process, report = self.exercise(protocol=True, milter_reply=b"")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["status"], "service_probe_failed")
        self.assertFalse(report["services"]["milter"]["protocol_verified"])

    def test_opt_in_milter_protocol_refuses_unoffered_capability(self):
        bad = struct.pack("!I", 13) + b"O" + struct.pack("!III", 6, 0x80000031, 0)
        process, report = self.exercise(protocol=True, milter_reply=bad)
        self.assertEqual(process.returncode, 1)
        self.assertIn("unoffered", report["services"]["milter"]["error"])

    def test_opt_in_milter_required_action_missing(self):
        subset = struct.pack("!I", 13) + b"O" + struct.pack("!III", 6, 0x01, 0)
        process, report = self.exercise(protocol=True, milter_reply=subset, required_actions="quarantine")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["status"], "service_probe_failed")
        self.assertIn("quarantine", report["services"]["milter"]["error"])

    def test_milter_protocol_requires_explicit_opt_in(self):
        process = subprocess.run([sys.executable, str(SCRIPT), "--verify-milter-protocol"],
                                 text=True, capture_output=True, timeout=8)
        self.assertEqual(process.returncode, 2)
        process = subprocess.run([sys.executable, str(SCRIPT), "--check-services",
                                  "--require-milter-actions", "quarantine"],
                                 text=True, capture_output=True, timeout=8)
        self.assertEqual(process.returncode, 2)

    def test_milter_action_list_rejects_duplicates_and_unknown(self):
        for actions in ("", "quarantine,quarantine", "quarantine,unknown", ",add_header"):
            process = subprocess.run([sys.executable, str(SCRIPT), "--check-services",
                                      "--verify-milter-protocol", "--require-milter-actions", actions],
                                     text=True, capture_output=True, timeout=8)
            self.assertEqual(process.returncode, 2, actions)

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

    def test_health_wrong_content_type_refused(self):
        process, report = self.exercise(content_type="text/html")
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["status"], "service_probe_failed")
        self.assertIn("Content-Type", report["services"]["health"]["error"])

    def test_health_invalid_utf8_refused_with_json_report(self):
        process, report = self.exercise(body=b'{"status":"ok","version":"' + bytes([0xff]) + b'"}')
        self.assertEqual(process.returncode, 1)
        self.assertEqual(report["status"], "service_probe_failed")
        self.assertEqual(report["services"]["health"]["error_type"], "ValueError")

    def test_health_duplicate_status_refused(self):
        body = b'{"status":"failed","status":"ok","version":"0.6.0-beta.2"}'
        process, report = self.exercise(body=body)
        self.assertEqual(process.returncode, 1)
        self.assertIn("duplicate", report["services"]["health"]["error"])

    def test_health_nonfinite_json_refused(self):
        process, report = self.exercise(body=b'{"status":"ok","version":"0.6.0-beta.2","metric":NaN}')
        self.assertEqual(process.returncode, 1)
        self.assertIn("non-finite", report["services"]["health"]["error"])

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
