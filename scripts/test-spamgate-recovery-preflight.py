#!/usr/bin/env python3
"""Native recovery preflight regression tests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).with_name("spamgate-recovery-preflight.py")

def run(path):
    return subprocess.run([sys.executable, str(TOOL), "--data", str(path)],
                          capture_output=True, text=True, timeout=15)

class RecoveryPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()

    def test_regular_tree_is_accepted(self):
        (self.data / "mail").mkdir()
        (self.data / "mail" / "one.eml").write_bytes(b"hello")
        result = run(self.data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["safe_for_offline_snapshot"])

    def test_symlink_is_refused(self):
        (self.data / "alias").symlink_to(self.root)
        result = run(self.data)
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink:", result.stdout)

    def test_hardlink_is_refused(self):
        first = self.data / "one"
        first.write_bytes(b"x")
        os.link(first, self.data / "two")
        result = run(self.data)
        self.assertEqual(result.returncode, 2)
        self.assertIn("hardlinked file:", result.stdout)

    def test_fifo_is_refused(self):
        os.mkfifo(self.data / "pipe")
        result = run(self.data)
        self.assertEqual(result.returncode, 2)
        self.assertIn("special file:", result.stdout)

    def test_missing_root_is_refused(self):
        result = run(self.root / "missing")
        self.assertEqual(result.returncode, 2)

    def test_symlink_root_is_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.data, target_is_directory=True)
        result = run(alias)
        self.assertEqual(result.returncode, 2)

    def test_relative_path_is_refused(self):
        result = run(Path("relative"))
        self.assertEqual(result.returncode, 2)

if __name__ == "__main__":
    unittest.main()
