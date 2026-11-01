"""Hostile subprocess regressions; no Postfix, Dovecot or mail host is touched."""
import sys
import time
import unittest

from spamgate_bounded_command import CommandProbeError, capture_command


class BoundedCommandTests(unittest.TestCase):
    def run_python(self, source, **kwargs):
        return capture_command([sys.executable, "-c", source], **kwargs)

    def test_success_preserves_exact_bytes_and_exit_code(self):
        out, err, code = self.run_python("import sys; sys.stdout.buffer.write(b'abc\\x00'); sys.stderr.write('warn'); sys.exit(7)")
        self.assertEqual((out, err, code), (b"abc\x00", b"warn", 7))

    def test_maximum_allowed_output(self):
        out, err, code = self.run_python("print('x'*63, end='')", max_bytes=63)
        self.assertEqual((len(out), err, code), (63, b"", 0))

    def test_stdout_flood_is_bounded(self):
        start = time.monotonic()
        with self.assertRaisesRegex(CommandProbeError, "output exceeds limit"):
            self.run_python("import os; os.write(1, b'x'*1000000)", max_bytes=256)
        self.assertLess(time.monotonic() - start, 3)

    def test_stderr_flood_is_bounded(self):
        with self.assertRaisesRegex(CommandProbeError, "output exceeds limit"):
            self.run_python("import os; os.write(2, b'secret'*100000)", max_bytes=256)

    def test_timeout_is_bounded(self):
        start = time.monotonic()
        with self.assertRaisesRegex(CommandProbeError, "timed out"):
            self.run_python("import time; time.sleep(10)", timeout=0.15)
        self.assertLess(time.monotonic() - start, 3)

    def test_forked_child_cannot_hold_pipe_open(self):
        source = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)']);print('done')"
        start = time.monotonic()
        with self.assertRaisesRegex(CommandProbeError, "timed out"):
            self.run_python(source, timeout=0.3)
        self.assertLess(time.monotonic() - start, 3)

    def test_nonexistent_executable_fails_without_path_leak(self):
        with self.assertRaisesRegex(CommandProbeError, "could not be executed") as ctx:
            capture_command(["/no/such/executable"])
        self.assertNotIn("/no/such", str(ctx.exception))

    def test_argv_and_limits_validation(self):
        for argv, kw in (([], {}), (["echo", ""], {}), (["echo", "x\x00"], {}),
                         (["echo"], {"timeout": 0}), (["echo"], {"max_bytes": 0}),
                         (["echo"], {"max_bytes": 1048577})):
            with self.subTest(argv=argv, kw=kw), self.assertRaises(CommandProbeError):
                capture_command(argv, **kw)

    def test_invalid_utf8_is_preserved_for_caller_validation(self):
        out, err, code = self.run_python("import os;os.write(1,b'\\xff')")
        self.assertEqual((out, err, code), (b"\xff", b"", 0))


if __name__ == "__main__":
    unittest.main()
