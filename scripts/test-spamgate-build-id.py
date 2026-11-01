#!/usr/bin/env python3
import datetime as dt
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import importlib.util

module_path = Path(__file__).with_name("spamgate-build-id.py")
spec = importlib.util.spec_from_file_location("spamgate_build_id", module_path)
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class BuildVersionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / "releases"

    def test_eastern_hours(self):
        cases = [
            ("2026-11-01T05:30:00+00:00", "20261101-01"),
            ("2026-11-01T06:30:00+00:00", "20261101-01"),
            ("2026-11-01T07:00:00+00:00", "20261101-02"),
            ("2026-07-01T04:00:00+00:00", "20260701-00"),
            ("2026-11-01T03:30:00+00:00", "20261031-23"),
        ]
        for source, expected in cases:
            self.assertEqual(build.base_id(dt.datetime.fromisoformat(source)), expected)

    def test_automatic_has_no_suffix_and_cannot_be_reused(self):
        self.assertEqual(build.reserve(self.out, "20261101-01", "automatic", None), "20261101-01")
        with self.assertRaisesRegex(ValueError, "already reserved"):
            build.reserve(self.out, "20261101-01", "automatic", None)

    def test_manual_letters_increment_and_are_never_reused(self):
        self.assertEqual(build.reserve(self.out, "20261101-01", "manual", None), "20261101-01a")
        self.assertEqual(build.reserve(self.out, "20261101-01", "manual", None), "20261101-01b")
        self.assertEqual(build.reserve(self.out, "20261101-01", "manual", "d"), "20261101-01d")
        self.assertEqual(build.reserve(self.out, "20261101-01", "manual", None), "20261101-01c")
        self.assertEqual(build.reserve(self.out, "20261101-02", "manual", None), "20261101-02a")
        self.assertEqual(build.reserve(self.out, "20261101-01", "automatic", None), "20261101-01")

    def test_all_manual_suffixes_exhaust(self):
        for index, letter in enumerate("abcdefghijklmnopqrstuvwxyz"):
            self.assertEqual(build.reserve(self.out, "20261101-01", "manual", None), "20261101-01" + letter)
        with self.assertRaisesRegex(ValueError, "all 26"):
            build.reserve(self.out, "20261101-01", "manual", None)

    def test_manual_rejects_bad_letter(self):
        for suffix in ["A", "aa", "0", "../x", ""]:
            with self.assertRaises(ValueError):
                build.reserve(self.out, "20261101-01", "manual", suffix)
        with self.assertRaises(ValueError):
            build.reserve(self.out, "20261101-01", "automatic", "a")

    def test_build_timestamp_requires_offset(self):
        with self.assertRaises(ValueError):
            build.base_id(dt.datetime(2026, 11, 1, 1, 30))

    def test_cannot_follow_symlinked_ledger(self):
        self.out.mkdir()
        target = self.out / "other"
        target.write_text("20261101-01a\n")
        (self.out / build.LEDGER).symlink_to(target)
        with self.assertRaises(OSError):
            build.reserve(self.out, "20261101-01", "manual", None)
        self.assertEqual(target.read_text(), "20261101-01a\n")

    def test_cannot_use_group_writable_reservation_directory(self):
        self.out.mkdir()
        self.out.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "writable"):
            build.reserve(self.out, "20261101-01", "manual", None)

    def test_dst_repeated_hour_is_never_silently_reused(self):
        first = build.base_id(dt.datetime.fromisoformat("2026-11-01T05:30:00+00:00"))
        second = build.base_id(dt.datetime.fromisoformat("2026-11-01T06:30:00+00:00"))
        self.assertEqual(first, second)
        build.reserve(self.out, first, "automatic", None)
        with self.assertRaisesRegex(ValueError, "already reserved"):
            build.reserve(self.out, second, "automatic", None)


if __name__ == "__main__":
    unittest.main()
