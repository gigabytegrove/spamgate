"""Real TCP Milter OPTNEG protocol tests without SMTP or mail-server changes."""
import importlib.util
import pathlib
import socket
import struct
import threading
import unittest

MODULE = pathlib.Path(__file__).with_name("spamgate_milter_probe.py")
spec = importlib.util.spec_from_file_location("spamgate_milter_probe", MODULE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def frame(command=b"O", version=6, actions=0x31, protocol=0):
    return struct.pack("!I", 13) + command + struct.pack("!III", version, actions, protocol)


class MilterProbeTests(unittest.TestCase):
    def exercise(self, response, *, fragments=False):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            seen = []
            def peer():
                with listener.accept()[0] as conn:
                    conn.settimeout(1)
                    payload = bytearray()
                    while len(payload) < 17:
                        chunk = conn.recv(17 - len(payload))
                        if not chunk:
                            break
                        payload.extend(chunk)
                    seen.append(bytes(payload))
                    try:
                        if fragments:
                            for b in response:
                                conn.sendall(bytes([b]))
                        else:
                            conn.sendall(response)
                    except OSError:
                        pass
            worker = threading.Thread(target=peer, daemon=True)
            worker.start()
            try:
                with socket.create_connection(listener.getsockname(), timeout=1) as conn:
                    conn.settimeout(1)
                    try:
                        result = probe.verify_milter_protocol(conn)
                    except probe.MilterProtocolError as exc:
                        result = str(exc)
            finally:
                worker.join(timeout=2)
            self.assertFalse(worker.is_alive(), "peer did not terminate")
            self.assertEqual(seen, [frame()])
            return result

    def test_valid_negotiation_with_fragmented_tcp_reply(self):
        result = self.exercise(frame(), fragments=True)
        self.assertTrue(result["protocol_verified"])
        self.assertEqual(result["negotiated_version"], 6)
        self.assertEqual(result["negotiated_actions"], {
            "add_header": True, "change_header": True, "quarantine": True})

    def test_valid_downgrade_and_subset(self):
        result = self.exercise(frame(version=5, actions=1))
        self.assertEqual(result["negotiated_version"], 5)
        self.assertFalse(result["negotiated_actions"]["quarantine"])

    def test_refuses_unsupported_version(self):
        self.assertIn("version", self.exercise(frame(version=7)))
        self.assertIn("version", self.exercise(frame(version=1)))

    def test_refuses_unoffered_actions(self):
        self.assertIn("unoffered", self.exercise(frame(actions=0x80000031)))

    def test_refuses_protocol_shortcuts(self):
        self.assertIn("shortcuts", self.exercise(frame(protocol=1)))

    def test_refuses_wrong_command(self):
        self.assertIn("command", self.exercise(frame(command=b"c")))

    def test_refuses_bad_length_before_payload(self):
        self.assertIn("length", self.exercise(struct.pack("!I", 0)))
        self.assertIn("length", self.exercise(struct.pack("!I", 65536)))
        self.assertIn("length", self.exercise(struct.pack("!I", 12) + frame()[4:]))

    def test_refuses_truncated_reply(self):
        self.assertIn("truncated", self.exercise(frame()[:9]))
        self.assertIn("truncated", self.exercise(frame()[:2]))

    def test_no_response_is_not_a_success(self):
        self.assertIn("truncated", self.exercise(b""))


if __name__ == "__main__":
    unittest.main()
