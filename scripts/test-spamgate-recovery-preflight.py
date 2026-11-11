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

    def test_mountinfo_detects_nested_bind_mount(self):
        spec = importlib.util.spec_from_file_location("preflight", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        mountinfo = self.root / "mountinfo"
        mountinfo.write_text(
            "10 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
            f"11 10 8:1 /other {self.data}/nested rw - ext4 /dev/sda1 rw\n"
        )
        mounts, error = module.nested_mounts(self.data, str(mountinfo))
        self.assertIsNone(error)
        self.assertEqual(mounts, [str(self.data / "nested")])

    def test_mountinfo_decodes_escaped_spaces(self):
        spec = importlib.util.spec_from_file_location("preflight", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        mountinfo = self.root / "mountinfo"
        mountinfo.write_text(
            "11 10 8:1 /other " + str(self.data) + "/my\\040mount rw - ext4 /dev/sda1 rw\n"
        )
        mounts, error = module.nested_mounts(self.data, str(mountinfo))
        self.assertIsNone(error)
        self.assertEqual(mounts, [str(self.data / "my mount")])

    def test_missing_mountinfo_fails_closed(self):
        spec = importlib.util.spec_from_file_location("preflight", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with mock.patch.object(module, "nested_mounts", return_value=([], "mount table unavailable")):
            findings = module.check(self.data)
        self.assertIn("mount table unavailable", findings)

    def test_nested_mount_is_refused_without_crossing_it(self):
        spec = importlib.util.spec_from_file_location("preflight", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        nested = self.data / "nested"
        nested.mkdir()
        with mock.patch.object(module, "nested_mounts", return_value=([str(nested)], None)):
            findings = module.check(self.data)
        self.assertIn("nested mount point: " + str(nested), findings)

    def test_dotdot_component_is_refused(self):
        result = run(self.data / ".." / "data")
        self.assertEqual(result.returncode, 2)
        self.assertIn("parent traversal", result.stdout)

    def test_dot_component_is_refused(self):
        result = run(str(self.data) + "/./")
        self.assertEqual(result.returncode, 2)
        self.assertIn("dot or parent traversal", result.stdout)

    def test_nested_mount_is_not_traversed(self):
        spec = importlib.util.spec_from_file_location("preflight", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        nested = self.data / "nested"
        nested.mkdir()
        (nested / "should-not-be-visited").write_text("x")
        real_walk = module.os.walk
        visited = []

        def traced_walk(*args, **kwargs):
            for item in real_walk(*args, **kwargs):
                visited.append(str(item[0]))
                yield item

        with mock.patch.object(module, "nested_mounts", return_value=([str(nested)], None)):
            with mock.patch.object(module.os, "walk", side_effect=traced_walk):
                findings = module.check(self.data)
        self.assertIn("nested mount point: " + str(nested), findings)
        self.assertNotIn(str(nested), visited)

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
