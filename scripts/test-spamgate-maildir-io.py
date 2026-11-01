"""Race and symlink regressions for descriptor-anchored Maildir evidence."""
import os
import pathlib
import tempfile
import unittest

from spamgate_maildir_io import check_message_identity, open_directory, open_maildir_child


class MaildirIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.root = self.base / "Maildir"
        (self.root / "new").mkdir(parents=True)
        (self.root / "cur").mkdir()
        self.message = self.root / "new" / "message"
        self.message.write_text("Message-ID: <test@example.org>\n\n")

    def test_descriptor_relative_child_reads_regular_file(self):
        with open_directory(self.root) as root_fd:
            with open_maildir_child(root_fd, "new") as fd:
                with os.scandir(fd) as listing:
                    self.assertEqual([entry.name for entry in listing], ["message"])

    def test_parent_path_replacement_cannot_redirect_child(self):
        replacement = self.base / "replacement"
        (replacement / "new").mkdir(parents=True)
        (replacement / "new" / "attacker").write_text("unrelated")
        with open_directory(self.root) as root_fd:
            self.root.rename(self.base / "original")
            self.root.symlink_to(replacement, target_is_directory=True)
            with open_maildir_child(root_fd, "new") as fd:
                with os.scandir(fd) as listing:
                    self.assertEqual([entry.name for entry in listing], ["message"])

    def test_root_symlink_refused(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "real directory"):
            with open_directory(alias):
                pass

    def test_child_symlink_refused(self):
        (self.root / "cur").rmdir()
        (self.root / "cur").symlink_to(self.root / "new", target_is_directory=True)
        with open_directory(self.root) as root_fd:
            with self.assertRaises(OSError):
                with open_maildir_child(root_fd, "cur"):
                    pass

    def test_child_name_restricted(self):
        with open_directory(self.root) as root_fd:
            with self.assertRaisesRegex(ValueError, "unsupported"):
                with open_maildir_child(root_fd, "../new"):
                    pass

    def test_stable_message_identity_accepted(self):
        listed = os.stat(self.message)
        with self.message.open("rb") as handle:
            before = os.fstat(handle.fileno())
            handle.read()
            after = os.fstat(handle.fileno())
        check_message_identity(listed, before, after)

    def test_replaced_message_inode_refused(self):
        listed = os.stat(self.message)
        replacement = self.base / "replacement-file"
        replacement.write_bytes(self.message.read_bytes())
        os.replace(replacement, self.message)
        with self.message.open("rb") as handle:
            now = os.fstat(handle.fileno())
        with self.assertRaisesRegex(ValueError, "changed"):
            check_message_identity(listed, now, now)

    def test_in_place_message_growth_refused(self):
        with self.message.open("r+b") as handle:
            before = os.fstat(handle.fileno())
            handle.seek(0, os.SEEK_END)
            handle.write(b"changed")
            handle.flush()
            after = os.fstat(handle.fileno())
        with self.assertRaisesRegex(ValueError, "changed"):
            check_message_identity(before, before, after)

    def test_nonregular_message_refused(self):
        info = os.stat(self.root)
        with self.assertRaisesRegex(ValueError, "changed"):
            check_message_identity(info, info, info)


if __name__ == "__main__":
    unittest.main()
