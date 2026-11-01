"""Hermetic Dovecot LDA Sieve probe tests. No live service or mailbox writes."""
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from spamgate_dovecot_config_probe import (
    DovecotProbeError, EXPECTED_FILES, inspect_config, inspect_installed_files,
    parse_doveconf, probe_dovecot_sieve)

SCRIPT = pathlib.Path(__file__).with_name("spamgate-host-probe.py")
GOOD = """# 2.3 Dovecot
service imap-login {
  inet_listener imaps {
    port = 993
  }
}
protocol lmtp {
  mail_plugins = sieve
}
protocol lda {
  mail_plugins = $mail_plugins sieve
}
plugin {
  sieve_before = /etc/dovecot/sieve/spamgate-junk.sieve
}
"""


class DovecotConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name, "etc")
        (self.root / "sieve").mkdir(parents=True)
        (self.root / "conf.d").mkdir()
        hashes = []
        for i, absolute in enumerate(EXPECTED_FILES):
            file = self.root / pathlib.PurePosixPath(absolute).relative_to("/etc/dovecot")
            content = ("test fixture %d\n" % i).encode()
            file.write_bytes(content)
            file.chmod(0o644)
            hashes.append("%s  %s\n" % (hashlib.sha256(content).hexdigest(), absolute))
        manifest = self.root / "conf.d/99-spamgate-junk.sha256"
        manifest.write_text("".join(hashes))
        manifest.chmod(0o600)

    def test_valid_config_and_manifest(self):
        self.assertEqual(inspect_config(GOOD), [])
        self.assertTrue(inspect_installed_files(self.root))

    def test_nested_lmtp_sieve_not_mistaken_for_lda(self):
        value = GOOD.replace("protocol lda {\n  mail_plugins = $mail_plugins sieve\n}\n", "")
        self.assertIn("lda_sieve_plugin_not_explicitly_enabled", inspect_config(value))

    def test_explicit_lmtp_path_with_independent_plugin(self):
        self.assertEqual(inspect_config(GOOD, delivery_path="lmtp"), [])
        lmtp_only = GOOD.replace("protocol lda {\n  mail_plugins = $mail_plugins sieve\n}\n", "")
        self.assertEqual(inspect_config(lmtp_only, delivery_path="lmtp"), [])
        self.assertIn("lda_sieve_plugin_not_explicitly_enabled", inspect_config(lmtp_only))

    def test_lmtp_does_not_inherit_lda_plugin(self):
        lda_only = GOOD.replace("protocol lmtp {\n  mail_plugins = sieve\n}\n", "")
        self.assertEqual(inspect_config(lda_only, delivery_path="lda"), [])
        self.assertIn("lmtp_sieve_plugin_not_explicitly_enabled",
                      inspect_config(lda_only, delivery_path="lmtp"))

    def test_lmtp_requires_sieve_not_just_other_plugins(self):
        raw = GOOD.replace("protocol lmtp {\n  mail_plugins = sieve",
                           "protocol lmtp {\n  mail_plugins = quota")
        self.assertIn("lmtp_sieve_plugin_not_explicitly_enabled",
                      inspect_config(raw, delivery_path="lmtp"))

    def test_nested_lmtp_does_not_qualify_top_level(self):
        nested = GOOD.replace("protocol lmtp {\n  mail_plugins = sieve\n}\n", "")
        nested += "service lmtp {\n protocol lmtp {\n mail_plugins = sieve\n }\n}\n"
        self.assertIn("lmtp_sieve_plugin_not_explicitly_enabled",
                      inspect_config(nested, delivery_path="lmtp"))

    def test_duplicate_lmtp_section_rejected(self):
        with self.assertRaises(DovecotProbeError):
            inspect_config(GOOD + "protocol lmtp {\n mail_plugins = sieve\n}\n",
                           delivery_path="lmtp")

    def test_duplicate_lmtp_setting_rejected(self):
        raw = GOOD.replace("protocol lmtp {\n  mail_plugins = sieve",
                           "protocol lmtp {\n  mail_plugins = sieve\n  mail_plugins = sieve")
        with self.assertRaises(DovecotProbeError):
            inspect_config(raw, delivery_path="lmtp")

    def test_lmtp_missing_global_rule_is_not_qualified(self):
        raw = GOOD.replace("sieve_before =", "sieve_after =")
        self.assertIn("spamgate_sieve_before_not_configured",
                      inspect_config(raw, delivery_path="lmtp"))

    def test_invalid_direct_delivery_path_is_rejected(self):
        for path in ("", "smtp", "LDA", "../lmtp", None):
            with self.subTest(path=path):
                with self.assertRaises(DovecotProbeError):
                    inspect_config(GOOD, delivery_path=path)

    def test_missing_sieve_before_refused(self):
        self.assertIn("spamgate_sieve_before_not_configured",
                      inspect_config(GOOD.replace("sieve_before =", "other =")))

    def test_wrong_sieve_path_refused(self):
        self.assertIn("spamgate_sieve_before_not_configured",
                      inspect_config(GOOD.replace("spamgate-junk.sieve", "other.sieve")))

    def test_duplicate_lda_scope_refused(self):
        with self.assertRaises(DovecotProbeError):
            inspect_config(GOOD + "protocol lda {\n mail_plugins = sieve\n}\n")

    def test_duplicate_plugin_key_refused(self):
        with self.assertRaises(DovecotProbeError):
            inspect_config(GOOD.replace("  sieve_before =", "  sieve_before = /tmp/other\n  sieve_before ="))

    def test_unbalanced_config_refused(self):
        with self.assertRaises(DovecotProbeError):
            parse_doveconf(GOOD + "protocol lda {\n")

    def test_manifest_tamper_refused(self):
        (self.root / "sieve/spamgate-junk.sieve").write_text("modified")
        with self.assertRaises(DovecotProbeError):
            inspect_installed_files(self.root)

    def test_manifest_extra_entry_refused(self):
        with (self.root / "conf.d/99-spamgate-junk.sha256").open("a") as f:
            f.write("a" * 64 + "  /etc/dovecot/extra\n")
        with self.assertRaises(DovecotProbeError):
            inspect_installed_files(self.root)

    def test_symlink_refused(self):
        file = self.root / "sieve/spamgate-junk.sieve"
        other = self.root / "outside"
        other.write_text("test")
        file.unlink()
        file.symlink_to(other)
        with self.assertRaises(DovecotProbeError):
            inspect_installed_files(self.root)

    def test_world_writable_refused(self):
        (self.root / "sieve/spamgate-junk.svbin").chmod(0o666)
        with self.assertRaises(DovecotProbeError):
            inspect_installed_files(self.root)

    def test_missing_compiled_file_refused(self):
        (self.root / "sieve/spamgate-junk.svbin").unlink()
        with self.assertRaises(DovecotProbeError):
            inspect_installed_files(self.root)

    def test_bounded_snapshot(self):
        with self.assertRaises(DovecotProbeError):
            inspect_config(GOOD + "x" * 70000)

    def test_success_with_fake_readonly_doveconf(self):
        binary = pathlib.Path(self.tmp.name, "doveconf")
        binary.write_text("#!/bin/sh\n[ \"$1\" = -n ] || exit 99\ncat <<'CONFIG'\n" + GOOD + "CONFIG\n")
        binary.chmod(0o700)
        report = probe_dovecot_sieve(executable=str(binary), root=self.root)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["scope"], "dovecot_lda_configuration_only")
        self.assertNotIn("mail_plugins", json.dumps(report))

    def test_lmtp_success_with_fake_readonly_doveconf(self):
        binary = pathlib.Path(self.tmp.name, "doveconf-lmtp")
        binary.write_text("#!/bin/sh\n[ \"$1\" = -n ] || exit 99\ncat <<'CONFIG'\n" + GOOD + "CONFIG\n")
        binary.chmod(0o700)
        report = probe_dovecot_sieve(executable=str(binary), root=self.root,
                                     delivery_path="lmtp")
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["delivery_path"], "lmtp")
        self.assertEqual(report["status"], "lmtp_sieve_config_checked")
        self.assertEqual(report["scope"], "dovecot_lmtp_configuration_only")
        self.assertNotIn("mail_plugins", json.dumps(report))
        self.assertIn("Postfix routing", " ".join(report["limitations"]))

    def test_invalid_library_path_is_privacy_safe(self):
        report = probe_dovecot_sieve(delivery_path="invalid-secret-path")
        self.assertFalse(report["ok"])
        self.assertIsNone(report["delivery_path"])
        self.assertNotIn("invalid-secret-path", json.dumps(report))

    def test_cli_lmtp_requires_check_flag(self):
        for args in (["--dovecot-delivery-path", "lmtp"],
                     ["--check-dovecot-sieve", "--dovecot-delivery-path", "smtp"]):
            result = subprocess.run([sys.executable, str(SCRIPT), *args],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_cli_lmtp_failure_blocks_smtp(self):
        env = dict(os.environ, PATH=self.tmp.name)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--check-dovecot-sieve",
             "--dovecot-delivery-path", "lmtp", "--send",
             "--sender", "probe@example.org", "--recipient", "test@example.org",
             "--confirm-recipient", "test@example.org"],
            capture_output=True, text=True, timeout=10, env=env)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "dovecot_sieve_failed")
        self.assertEqual(report["dovecot_sieve"]["delivery_path"], "lmtp")
        self.assertFalse(report["smtp"]["attempted"])

    def test_bad_doveconf_refused_without_config_leak(self):
        binary = pathlib.Path(self.tmp.name, "doveconf")
        binary.write_text("#!/bin/sh\necho 'secret_password = topsecret' >&2\nexit 1\n")
        binary.chmod(0o700)
        report = probe_dovecot_sieve(executable=str(binary), root=self.root)
        self.assertFalse(report["ok"])
        self.assertNotIn("topsecret", json.dumps(report))

    def test_cli_opt_in_missing_doveconf_blocks_send(self):
        env = dict(os.environ, PATH=self.tmp.name)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--check-dovecot-sieve",
             "--send", "--sender", "probe@example.org", "--recipient", "test@example.org",
             "--confirm-recipient", "test@example.org"],
            capture_output=True, text=True, timeout=10, env=env)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "dovecot_sieve_failed")
        self.assertFalse(report["smtp"]["attempted"])

    def test_default_probe_does_not_attempt_dovecot(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["dovecot_sieve"], {"attempted": False})

    def test_doveconf_output_flood_fails_closed_without_leaking_output(self):
        binary = pathlib.Path(self.tmp.name, "doveconf-flood")
        binary.write_text("#!/bin/sh\nwhile :; do printf 'secret-value'; done\n")
        binary.chmod(0o700)
        report = probe_dovecot_sieve(executable=str(binary), root=self.root)
        self.assertFalse(report["ok"])
        self.assertIn("output exceeds limit", report["error"])
        self.assertNotIn("secret-value", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
