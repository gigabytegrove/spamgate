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

    def test_extra_snapshot_root_entry_refused(self):
        self.make_backup()
        (self.backup / "unexpected").write_text("hidden")
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_symlinked_manifest_refused(self):
        self.make_backup()
        manifest = self.backup / "manifest.json"
        replacement = self.root / "manifest-copy.json"
        replacement.write_bytes(manifest.read_bytes())
        manifest.unlink()
        manifest.symlink_to(replacement)
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_symlinked_payload_directory_refused(self):
        self.make_backup()
        payload = self.backup / "files"
        payload.rename(self.root / "payload")
        payload.symlink_to(self.root / "payload", target_is_directory=True)
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_source_root_symlink_refused(self):
        alias = self.root / "alias"
        alias.symlink_to(self.data, target_is_directory=True)
        self.assertNotEqual(invoke("snapshot", "--source", alias, "--target",
                                   self.backup, "--acknowledge-offline").returncode, 0)

    def test_snapshot_target_ancestor_of_source_refused(self):
        result = invoke("snapshot", "--source", self.data, "--target", self.root,
                        "--acknowledge-offline")
        self.assertNotEqual(result.returncode, 0)

    def test_payload_permission_tampering_refused(self):
        import os
        self.make_backup()
        payload = self.backup / "files" / "state.json"
        original = payload.stat().st_mode & 0o777
        os.chmod(payload, original ^ 0o100)
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)
        destination = self.root / "restored"
        self.assertNotEqual(invoke("restore", "--source", self.backup,
                                   "--target", destination,
                                   "--acknowledge-offline").returncode, 0)
        self.assertFalse(destination.exists())

    def test_payload_permission_roundtrip(self):
        import os
        os.chmod(self.data / "state.json", 0o600)
        os.chmod(self.data / "messages" / "one.eml", 0o640)
        self.make_backup()
        destination = self.root / "restored"
        result = invoke("restore", "--source", self.backup, "--target",
                        destination, "--acknowledge-offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((destination / "state.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((destination / "messages" / "one.eml").stat().st_mode & 0o777, 0o640)

    def test_manifest_permission_mismatch_refused(self):
        self.make_backup()
        manifest = self.backup / "manifest.json"
        data = json.loads(manifest.read_text())
        data["files"][0]["mode"] ^= 0o100
        manifest.write_text(json.dumps(data))
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_directory_inventory_detects_mutations(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("offline_data", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        before = module.directory_inventory(self.data)
        (self.data / "new.eml").write_bytes(b"new")
        self.assertNotEqual(before, module.directory_inventory(self.data))
        (self.data / "new.eml").unlink()
        (self.data / "empty").mkdir()
        self.assertNotEqual(before, module.directory_inventory(self.data))

    def test_restored_stage_rejects_corruption(self):
        import importlib.util
        import shutil
        spec = importlib.util.spec_from_file_location("offline_data", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.make_backup()
        entries = module.verify(self.backup)
        stage = self.root / "stage"
        shutil.copytree(self.backup / "files", stage, copy_function=shutil.copy2)
        module.verify_restored_stage(stage, entries)
        (stage / "state.json").write_bytes(b"corrupt")
        with self.assertRaises(module.SnapshotError):
            module.verify_restored_stage(stage, entries)

    def test_restored_stage_rejects_extra_file(self):
        import importlib.util
        import shutil
        spec = importlib.util.spec_from_file_location("offline_data", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.make_backup()
        stage = self.root / "stage"
        shutil.copytree(self.backup / "files", stage, copy_function=shutil.copy2)
        (stage / "extra").write_bytes(b"unexpected")
        with self.assertRaises(module.SnapshotError):
            module.verify_restored_stage(stage, module.verify(self.backup))

    def test_symlinked_snapshot_parent_refused(self):
        parent = self.root / "snapshot-parent"
        parent.symlink_to(self.root, target_is_directory=True)
        result = invoke("snapshot", "--source", self.data,
                        "--target", parent / "backup", "--acknowledge-offline")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.backup.exists())

    def test_symlinked_restore_parent_refused(self):
        self.make_backup()
        parent = self.root / "restore-parent"
        parent.symlink_to(self.root, target_is_directory=True)
        result = invoke("restore", "--source", self.backup,
                        "--target", parent / "restored", "--acknowledge-offline")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "restored").exists())

    def test_empty_nested_directories_survive_roundtrip(self):
        (self.data / "empty" / "nested").mkdir(parents=True)
        self.make_backup()
        manifest = json.loads((self.backup / "manifest.json").read_text())
        self.assertEqual(manifest["schema"], 3)
        self.assertIn("empty/nested", manifest["directories"])
        target = self.root / "restored"
        result = invoke("restore", "--source", self.backup, "--target", target,
                        "--acknowledge-offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((target / "empty" / "nested").is_dir())

    def test_extra_empty_payload_directory_refused(self):
        self.make_backup()
        (self.backup / "files" / "undeclared").mkdir()
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_missing_empty_payload_directory_refused(self):
        (self.data / "empty").mkdir()
        self.make_backup()
        (self.backup / "files" / "empty").rmdir()
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_duplicate_directory_manifest_refused(self):
        self.make_backup()
        manifest = self.backup / "manifest.json"
        data = json.loads(manifest.read_text())
        data["directories"].append(data["directories"][0])
        manifest.write_text(json.dumps(data))
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_schema_one_backward_compatibility(self):
        self.make_backup()
        manifest = self.backup / "manifest.json"
        data = json.loads(manifest.read_text())
        data["schema"] = 1
        del data["directories"]
        del data["directory_modes"]
        manifest.write_text(json.dumps(data))
        self.assertEqual(invoke("verify", "--source", self.backup).returncode, 0)
        target = self.root / "legacy-restore"
        result = invoke("restore", "--source", self.backup, "--target", target,
                        "--acknowledge-offline")
        self.assertEqual(result.returncode, 0, result.stderr)


    def test_directory_permissions_roundtrip(self):
        import os
        (self.data / "empty").mkdir()
        os.chmod(self.data / "empty", 0o750)
        os.chmod(self.data / "messages", 0o700)
        self.make_backup()
        target = self.root / "restored"
        result = invoke("restore", "--source", self.backup, "--target", target,
                        "--acknowledge-offline")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((target / "empty").stat().st_mode & 0o777, 0o750)
        self.assertEqual((target / "messages").stat().st_mode & 0o777, 0o700)

    def test_directory_permission_tampering_refused(self):
        import os
        self.make_backup()
        os.chmod(self.backup / "files" / "messages", 0o700)
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_directory_manifest_mode_invalid_refused(self):
        self.make_backup()
        manifest = self.backup / "manifest.json"
        data = json.loads(manifest.read_text())
        data["directory_modes"]["messages"] = 1024
        manifest.write_text(json.dumps(data))
        self.assertNotEqual(invoke("verify", "--source", self.backup).returncode, 0)

    def test_schema_two_backward_compatibility(self):
        self.make_backup()
        manifest = self.backup / "manifest.json"
        data = json.loads(manifest.read_text())
        data["schema"] = 2
        del data["directory_modes"]
        manifest.write_text(json.dumps(data))
        self.assertEqual(invoke("verify", "--source", self.backup).returncode, 0)
        target = self.root / "legacy-v2"
        result = invoke("restore", "--source", self.backup, "--target", target,
                        "--acknowledge-offline")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_manifest_file_directory_collision_refused(self):
        self.make_backup()
        manifest = self.backup / "manifest.json"
        data = json.loads(manifest.read_text())
        data["files"][0]["path"] = "messages"
        manifest.write_text(json.dumps(data))
        result = invoke("verify", "--source", self.backup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("collision", result.stderr)

    def test_manifest_file_parent_missing_refused(self):
        self.make_backup()
        manifest = self.backup / "manifest.json"
        data = json.loads(manifest.read_text())
        data["files"][0]["path"] = "undeclared/file.eml"
        manifest.write_text(json.dumps(data))
        result = invoke("verify", "--source", self.backup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("parent missing", result.stderr)

    def test_manifest_file_as_parent_refused_in_schema_one(self):
        self.make_backup()
        manifest = self.backup / "manifest.json"
        data = json.loads(manifest.read_text())
        data["schema"] = 1
        del data["directories"]
        del data["directory_modes"]
        data["files"][0]["path"] = "state.json/child"
        manifest.write_text(json.dumps(data))
        result = invoke("verify", "--source", self.backup)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("collision", result.stderr)

    def test_walk_refuses_traversal_errors(self):
        from unittest import mock
        spec = importlib.util.spec_from_file_location("offline_data", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        def broken_walk(root, followlinks=False, onerror=None):
            self.assertIsNotNone(onerror)
            onerror(PermissionError("unreadable nested directory"))
            yield root, [], []

        with mock.patch.object(module.os, "walk", side_effect=broken_walk):
            with self.assertRaisesRegex(module.SnapshotError, "filesystem traversal failed"):
                module.walk(self.data)
            with self.assertRaisesRegex(module.SnapshotError, "filesystem traversal failed"):
                module.directory_inventory(self.data)

    def test_snapshot_refuses_fifo_without_publishing(self):
        import os
        if not hasattr(os, "mkfifo"):
            self.skipTest("POSIX FIFO unavailable")
        os.mkfifo(self.data / "mail-pipe")
        result = invoke("snapshot", "--source", self.data, "--target", self.backup,
                        "--acknowledge-offline")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.backup.exists())

    def test_missing_snapshot_refused(self):
        result = invoke("verify", "--source", self.root / "missing")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
