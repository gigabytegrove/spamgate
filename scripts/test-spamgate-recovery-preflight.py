#!/usr/bin/env python3
"""Native recovery preflight regression tests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import importlib.util

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

    def test_symlinked_parent_is_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        result = run(alias / "data")
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlinked path component:", result.stdout)

    def test_filesystem_root_is_refused(self):
        result = run(Path("/"))
        self.assertEqual(result.returncode, 2)

    def test_traversal_error_is_reported(self):
        spec = importlib.util.spec_from_file_location("preflight", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        def broken_walk(*args, **kwargs):
            kwargs["onerror"](PermissionError(13, "denied", str(self.data / "blocked")))
            return iter(())

        with mock.patch.object(module.os, "walk", side_effect=broken_walk):
            findings = module.check(self.data)
        self.assertTrue(any("directory traversal failed:" in item for item in findings))


if __name__ == "__main__":
    unittest.main()
