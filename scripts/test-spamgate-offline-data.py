#!/usr/bin/env python3
"""Regression tests for the native offline data snapshot/restore tool."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(__file__).with_name("spamgate-offline-data.py")


def invoke(*args):
    return subprocess.run([sys.executable, str(TOOL), *map(str, args)],
                          text=True, capture_output=True, timeout=30)


class OfflineDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        (self.data / "messages").mkdir()
        (self.data / "messages" / "one.eml").write_bytes(b"From: a@example.net\n\nHello\n")
        (self.data / "state.json").write_text('{"count":1}\n')
        self.backup = self.root / "backup"

    def make_backup(self):
        result = invoke("snapshot", "--source", self.data, "--target", self.backup,
                        "--acknowledge-offline")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_snapshot_verify_restore_roundtrip(self):
        self.make_backup()
        self.assertEqual(invoke("verify", "--source", self.backup).returncode, 0)
        target = self.root / "restored"
        result = invoke("restore", "--source", self.backup, "--target", target,
                        "--acknowledge-offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((target / "messages" / "one.eml").read_bytes(),
                         (self.data / "messages" / "one.eml").read_bytes())
        self.assertEqual((target / "state.json").read_bytes(),
                         (self.data / "state.json").read_bytes())

    def test_explicit_offline_acknowledgement_required(self):
        result = invoke("snapshot", "--source", self.data, "--target", self.backup)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.backup.exists())

    def test_snapshot_never_overwrites(self):
        self.make_backup()
        result = invoke("snapshot", "--source", self.data, "--target", self.backup,
                        "--acknowledge-offline")
        self.assertNotEqual(result.returncode, 0)

    def test_restore_never_overwrites(self):
        self.make_backup()
        result = invoke("restore", "--source", self.backup, "--target", self.data,
                        "--acknowledge-offline")
        self.assertNotEqual(result.returncode, 0)

    def test_modified_bytes_fail_verification_and_restore(self):
        self.make_backup()
        (self.backup / "files" / "state.json").write_bytes(b"tampered")
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)
        destination = self.root / "restored"
        self.assertNotEqual(invoke("restore", "--source", self.backup, "--target",
                                   destination, "--acknowledge-offline").returncode, 0)
        self.assertFalse(destination.exists())

    def test_extra_file_fail_verification(self):
        self.make_backup()
        (self.backup / "files" / "unexpected").write_text("extra")
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_manifest_path_traversal_rejected(self):
        self.make_backup()
        manifest = self.backup / "manifest.json"
        data = json.loads(manifest.read_text())
        data["files"][0]["path"] = "../escape"
        manifest.write_text(json.dumps(data))
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_duplicate_json_key_rejected(self):
        self.make_backup()
        (self.backup / "manifest.json").write_text('{"schema":1,"schema":1,"files":[]}')
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_symlink_source_refused(self):
        (self.data / "link").symlink_to(self.root / "other")
        result = invoke("snapshot", "--source", self.data, "--target", self.backup,
                        "--acknowledge-offline")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.backup.exists())

    def test_hardlink_source_refused(self):
        import os
        os.link(self.data / "state.json", self.data / "alias.json")
        result = invoke("snapshot", "--source", self.data, "--target", self.backup,
                        "--acknowledge-offline")
        self.assertNotEqual(result.returncode, 0)

    def test_snapshot_inside_source_refused(self):
        result = invoke("snapshot", "--source", self.data,
                        "--target", self.data / "nested",
                        "--acknowledge-offline")
        self.assertNotEqual(result.returncode, 0)

    def test_missing_snapshot_refused(self):
        result = invoke("verify", "--source", self.root / "missing")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
