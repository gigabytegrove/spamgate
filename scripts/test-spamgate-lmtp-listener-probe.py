"""Real loopback TCP and Unix LMTP handshake tests; no mail is submitted."""
import json
import os
import pathlib
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from spamgate_lmtp_listener_probe import probe_lmtp_listener

SCRIPT = pathlib.Path(__file__).with_name("spamgate-host-probe.py")


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        behavior = self.server.behavior
        if behavior == "timeout":
            time.sleep(3.3)
            return
        if behavior == "bad_greeting":
            self.wfile.write(b"554 not ready\r\n")
            return
        if behavior == "oversized_greeting":
            self.wfile.write(b"220 " + b"A" * 600 + b"\r\n")
            return
        if behavior == "nonascii_greeting":
            self.wfile.write(b"220 \xff\r\n")
            return
        self.wfile.write(b"220 local LMTP ready\r\n")
        self.wfile.flush()
        command = self.rfile.readline(1024)
        self.server.commands.append(command)
        if command != b"LHLO spamgate-probe.invalid\r\n":
            return
        replies = {
            "good": b"250-local\r\n250-PIPELINING\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n",
            "bad_lhlo": b"500 command not supported\r\n",
            "mixed_codes": b"250-local\r\n550 PIPELINING\r\n",
            "missing_final": b"250-local\r\n250-PIPELINING\r\n",
            "many_lines": b"250-x\r\n" * 33,
            "invalid_code": b"25X not numeric\r\n",
            "bad_line_ending": b"250 local\n",
            "long_capability": b"250-" + b"A" * 600 + b"\r\n",
            "quit_refused": b"250 local\r\n",
            "quit_truncated": b"250 local\r\n",
            "privacy": b"250-local sensitivepassword\r\n250 AUTH secret\r\n",
        }
        self.wfile.write(replies.get(behavior, replies["good"]))
        self.wfile.flush()
        if behavior in ("missing_final", "many_lines", "bad_line_ending", "long_capability"):
            return
        if behavior in ("bad_lhlo", "mixed_codes", "invalid_code"):
            return
        command = self.rfile.readline(1024)
        self.server.commands.append(command)
        if command != b"QUIT\r\n":
            return
        if behavior == "quit_truncated":
            return
        self.wfile.write(b"500 refused\r\n" if behavior == "quit_refused" else b"221 goodbye\r\n")
        self.wfile.flush()


class TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, behavior):
        super().__init__(("127.0.0.1", 0), Handler)
        self.behavior = behavior
        self.commands = []


class UnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path, behavior):
        super().__init__(path, Handler)
        self.behavior = behavior
        self.commands = []


class LMTPTests(unittest.TestCase):
    def exercise(self, behavior="good", *, unix=False):
        with tempfile.TemporaryDirectory() as directory:
            if unix:
                server = UnixServer(str(pathlib.Path(directory) / "lmtp.sock"), behavior)
                kwargs = {"unix_socket": server.server_address}
            else:
                server = TCPServer(behavior)
                kwargs = {"tcp_port": server.server_address[1]}
            with server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    result = probe_lmtp_listener(**kwargs)
                    return result, list(server.commands)
                finally:
                    server.shutdown()
                    thread.join(timeout=4)

    def test_tcp_success_and_no_mail_commands(self):
        result, commands = self.exercise()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["transport"], "tcp_loopback")
        self.assertEqual(result["capabilities"], ["8BITMIME", "ENHANCEDSTATUSCODES", "PIPELINING"])
        self.assertEqual(commands, [b"LHLO spamgate-probe.invalid\r\n", b"QUIT\r\n"])
        self.assertNotIn("sensitivepassword", json.dumps(result))

    def test_unix_socket_success(self):
        result, commands = self.exercise(unix=True)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["transport"], "unix")
        self.assertEqual(len(commands), 2)

    def test_protocol_failures_are_rejected(self):
        for behavior in ("bad_greeting", "oversized_greeting", "nonascii_greeting",
                         "bad_lhlo", "mixed_codes", "missing_final", "many_lines",
                         "invalid_code", "bad_line_ending", "long_capability",
                         "quit_refused", "quit_truncated"):
            with self.subTest(behavior=behavior):
                result, _ = self.exercise(behavior)
                self.assertFalse(result["ok"], result)
                self.assertNotIn("local", json.dumps(result).lower())

    def test_timeout_is_bounded(self):
        start = time.monotonic()
        result, _ = self.exercise("timeout")
        self.assertFalse(result["ok"])
        self.assertLess(time.monotonic() - start, 6)

    def test_privacy_redacts_peer_text(self):
        result, commands = self.exercise("privacy")
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["capabilities"], ["AUTH"])
        self.assertNotIn("secret", json.dumps(result))
        self.assertEqual(len(commands), 2)

    def test_refuse_invalid_transport_arguments(self):
        for kwargs in ({}, {"tcp_port": 0}, {"tcp_port": 65536},
                       {"tcp_port": "25"}, {"tcp_port": True},
                       {"unix_socket": "relative"}, {"unix_socket": "/tmp/x\x00y"},
                       {"unix_socket": "/" + "a" * 120},
                       {"unix_socket": "/tmp/a", "tcp_port": 25}):
            with self.subTest(kwargs=kwargs):
                self.assertFalse(probe_lmtp_listener(**kwargs)["ok"])

    def test_symlink_and_regular_file_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            file = pathlib.Path(directory, "regular")
            file.write_text("not a socket")
            symlink = pathlib.Path(directory, "link")
            symlink.symlink_to(file)
            for path in (file, symlink):
                result = probe_lmtp_listener(unix_socket=str(path))
                self.assertFalse(result["ok"])
                self.assertIn("not a socket", result["error"])

    def test_missing_socket_refused(self):
        self.assertFalse(probe_lmtp_listener(unix_socket="/run/dovecot/nonexistent-spamgate-test.sock")["ok"])

    @unittest.skipUnless(SCRIPT.is_file(), "host probe source not mounted locally")
    def test_cli_opt_in_validation(self):
        for flags in (("--lmtp-tcp-port", "24"),
                      ("--lmtp-socket", "/run/dovecot/lmtp"),
                      ("--check-lmtp-listener", "--lmtp-tcp-port", "0"),
                      ("--check-lmtp-listener", "--lmtp-tcp-port", "24",
                       "--lmtp-socket", "/run/dovecot/lmtp")):
            with self.subTest(flags=flags):
                process = subprocess.run([sys.executable, str(SCRIPT), *flags],
                                         capture_output=True, text=True, timeout=10)
                self.assertEqual(process.returncode, 2, process.stderr)

    @unittest.skipUnless(SCRIPT.is_file(), "host probe source not mounted locally")
    def test_cli_tcp_listener_success_is_read_only(self):
        with TCPServer("good") as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                process = subprocess.run(
                    [sys.executable, str(SCRIPT), "--check-lmtp-listener",
                     "--lmtp-tcp-port", str(server.server_address[1])],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(process.returncode, 0, process.stderr)
                report = json.loads(process.stdout)
                self.assertEqual(report["status"], "preflight_only")
                self.assertTrue(report["lmtp_listener"]["ok"])
                self.assertFalse(report["smtp"]["attempted"])
                self.assertEqual(server.commands,
                                 [b"LHLO spamgate-probe.invalid\r\n", b"QUIT\r\n"])
            finally:
                server.shutdown()
                thread.join(timeout=4)

    @unittest.skipUnless(SCRIPT.is_file(), "host probe source not mounted locally")
    def test_cli_listener_failure_blocks_explicit_smtp(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        process = subprocess.run(
            [sys.executable, str(SCRIPT), "--check-lmtp-listener",
             "--lmtp-tcp-port", str(port), "--send", "--sender", "probe@example.org",
             "--recipient", "test@example.org", "--confirm-recipient", "test@example.org"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 1, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["status"], "lmtp_listener_failed")
        self.assertFalse(report["lmtp_listener"]["ok"])
        self.assertFalse(report["smtp"]["attempted"])

    @unittest.skipUnless(SCRIPT.is_file(), "host probe source not mounted locally")
    def test_cli_default_never_contacts_lmtp(self):
        process = subprocess.run([sys.executable, str(SCRIPT)],
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["lmtp_listener"], {"attempted": False})

    def test_closed_tcp_port_refused(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.assertFalse(probe_lmtp_listener(tcp_port=port)["ok"])


if __name__ == "__main__":
    unittest.main()
