"""Real file and gzip regressions, without access to production mail logs."""
import gzip
import os
import pathlib
import tempfile
import unittest
from spamgate_log_reader import bounded_log_lines


class LogReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)

    def write(self, name, payload):
        target = self.root / name
        target.write_bytes(payload)
        return target

    def test_plain_log(self):
        path = self.write("mail.log", b"first\nsecond\n")
        self.assertEqual(list(bounded_log_lines(path)), ["first\n", "second\n"])

    def test_gzip_rotated_log(self):
        path = self.write("mail.log.1.gz", gzip.compress(b"first\nsecond\n"))
        self.assertEqual(list(bounded_log_lines(path)), ["first\n", "second\n"])

    def test_magic_without_gz_extension(self):
        path = self.write("rotated", gzip.compress(b"line\n"))
        self.assertEqual(list(bounded_log_lines(path)), ["line\n"])

    def test_concatenated_gzip_members(self):
        path = self.write("mail.log.gz", gzip.compress(b"one\n") + gzip.compress(b"two\n"))
        self.assertEqual(list(bounded_log_lines(path)), ["one\n", "two\n"])

    def test_non_gzip_with_gz_extension_refused(self):
        path = self.write("mail.log.gz", b"not compressed\n")
        with self.assertRaises(ValueError):
            list(bounded_log_lines(path))

    def test_corrupt_gzip_refused(self):
        path = self.write("mail.log.gz", gzip.compress(b"line\n")[:-5])
        with self.assertRaises(ValueError):
            list(bounded_log_lines(path))

    def test_invalid_gzip_crc_refused(self):
        data = bytearray(gzip.compress(b"line\n"))
        data[-8] ^= 0x01
        path = self.write("mail.log.gz", bytes(data))
        with self.assertRaises(ValueError):
            list(bounded_log_lines(path))

    def test_expanded_line_limit_refused(self):
        path = self.write("mail.log.gz", gzip.compress(b"x" * 65537 + b"\n"))
        with self.assertRaisesRegex(ValueError, "oversized"):
            list(bounded_log_lines(path))

    def test_plain_line_limit_refused(self):
        path = self.write("mail.log", b"x" * 65537)
        with self.assertRaisesRegex(ValueError, "oversized"):
            list(bounded_log_lines(path))

    def test_symlink_refused(self):
        original = self.write("mail.log", b"line\n")
        link = self.root / "linked.log"
        link.symlink_to(original)
        with self.assertRaises(ValueError):
            list(bounded_log_lines(link))

    def test_directory_refused(self):
        with self.assertRaises(ValueError):
            list(bounded_log_lines(self.root))

    def test_nonexistent_log_refused(self):
        with self.assertRaises(FileNotFoundError):
            list(bounded_log_lines(self.root / "missing.log"))

    def test_expanded_total_limit_refused(self):
        path = self.write("bomb.gz", gzip.compress((b"x" * 1023 + b"\n") * 65536 + b"z"))
        with self.assertRaisesRegex(ValueError, "oversized"):
            list(bounded_log_lines(path))

    def test_in_place_append_during_scan_refused(self):
        path = self.write("mail.log", b"first\nsecond\n")
        reader = bounded_log_lines(path)
        self.assertEqual(next(reader), "first\n")
        with path.open("ab") as output:
            output.write(b"third\n")
        with self.assertRaisesRegex(ValueError, "changed during evidence read"):
            list(reader)

    def test_in_place_rewrite_same_size_refused(self):
        path = self.write("mail.log", b"first\nsecond\n")
        reader = bounded_log_lines(path)
        self.assertEqual(next(reader), "first\n")
        with path.open("r+b") as output:
            output.seek(6)
            output.write(b"THIRD\n")
            output.flush()
            os.fsync(output.fileno())
        with self.assertRaisesRegex(ValueError, "changed during evidence read"):
            list(reader)

    def test_gzip_append_during_scan_refused(self):
        path = self.write("mail.log.gz", gzip.compress(b"first\nsecond\n"))
        reader = bounded_log_lines(path)
        self.assertEqual(next(reader), "first\n")
        with path.open("ab") as output:
            output.write(gzip.compress(b"third\n"))
        with self.assertRaisesRegex(ValueError, "changed during evidence read"):
            list(reader)

    def test_path_replacement_during_scan_refused(self):
        path = self.write("mail.log", b"first\nsecond\n")
        reader = bounded_log_lines(path)
        self.assertEqual(next(reader), "first\n")
        replacement = self.write("replacement.log", b"first\nsecond\n")
        os.replace(replacement, path)
        with self.assertRaisesRegex(ValueError, "changed during evidence read"):
            list(reader)

    def test_path_removed_during_scan_refused(self):
        path = self.write("mail.log", b"first\nsecond\n")
        reader = bounded_log_lines(path)
        self.assertEqual(next(reader), "first\n")
        path.unlink()
        with self.assertRaisesRegex(ValueError, "changed during evidence read"):
            list(reader)

    def test_empty_log(self):
        path = self.write("mail.log", b"")
        self.assertEqual(list(bounded_log_lines(path)), [])


if __name__ == "__main__":
    unittest.main()
