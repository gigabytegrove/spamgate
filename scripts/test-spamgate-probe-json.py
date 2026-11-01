"""Health response parser safety: malformed responses cannot pass readiness."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from spamgate_probe_json import decode_health_response


class HealthJSONTests(unittest.TestCase):
    def test_valid_json_and_mime_parameter(self):
        got = decode_health_response(b'{"status":"ok","version":"0.6.0"}',
                                     "application/json; charset=utf-8")
        self.assertEqual(got["status"], "ok")

    def test_health_json_media_type(self):
        self.assertEqual(decode_health_response(b'{}', "application/health+json"), {})

    def test_reject_duplicate_nested_keys(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            decode_health_response(b'{"status":"ok","metadata":{"x":1,"x":2}}',
                                   "application/json")

    def test_reject_invalid_utf8(self):
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            decode_health_response(b'{"x":"' + bytes([0xff]) + b'"}', "application/json")

    def test_reject_nonfinite(self):
        for bad in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "non-finite"):
                decode_health_response(bad, "application/json")

    def test_reject_html_content_type(self):
        with self.assertRaisesRegex(ValueError, "Content-Type"):
            decode_health_response(b'{"status":"ok"}', "text/html")

    def test_reject_oversize(self):
        with self.assertRaisesRegex(ValueError, "4096-byte"):
            decode_health_response(b"x"*4097, "application/json")

    def test_reject_trailing_data(self):
        with self.assertRaises(ValueError):
            decode_health_response(b'{}{}', "application/json")

    def test_reject_excessive_nesting(self):
        with self.assertRaisesRegex(ValueError, "nesting"):
            decode_health_response(b"["*1500+b"0"+b"]"*1500, "application/json")


if __name__ == "__main__":
    unittest.main()
