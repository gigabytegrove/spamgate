"""Hermetic Postfix configuration evidence tests; no real MTA is accessed."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

from spamgate_postfix_config_probe import (
    EXPECTED_MILTER, PostfixConfigError, inspect_config, probe_postfix_config)

SCRIPT = pathlib.Path(__file__).with_name("spamgate-host-probe.py")
BASE = {
    "smtpd_milters": EXPECTED_MILTER,
    "non_smtpd_milters": "",
    "milter_protocol": "6",
    "milter_default_action": "tempfail",
}


class PostfixConfigProbeTests(unittest.TestCase):
    def test_safe_smtp_configuration_is_not_mailbox_qualification(self):
        result = inspect_config(BASE, "")
        self.assertTrue(result["ok"])
        self.assertTrue(result["smtpd_milter_attached"])
        self.assertFalse(result["non_smtpd_milter_attached"])
        self.assertEqual(result["scope"], "postfix_configuration_only")

    def test_extra_chain_requires_manual_review(self):
        values = dict(BASE, smtpd_milters="inet:127.0.0.1:11332, " + EXPECTED_MILTER)
        self.assertIn("smtp_milter_chain_requires_review",
                      inspect_config(values, "")["findings"])

    def test_duplicate_endpoint_is_not_qualified(self):
        values = dict(BASE, smtpd_milters=EXPECTED_MILTER + ", " + EXPECTED_MILTER)
        self.assertIn("smtp_milter_missing_or_duplicated",
                      inspect_config(values, "")["findings"])

    def test_missing_endpoint_is_not_qualified(self):
        values = dict(BASE, smtpd_milters="inet:127.0.0.1:11332")
        self.assertFalse(inspect_config(values, "")["ok"])

    def test_master_service_override_blocks_false_positive(self):
        # A continuation without a parameter name must never be accepted.
        with self.assertRaises(PostfixConfigError):
            inspect_config(BASE, "submission/inet/smtpd_milters =\n  inet:127.0.0.1:11332\n")

    def test_realistic_master_override_is_reported_without_value(self):
        report = inspect_config(BASE, "submission/inet/smtpd_milters = inet:127.0.0.1:11332\n")
        self.assertFalse(report["ok"])
        self.assertEqual(report["service_override_keys"], ["smtpd_milters"])
        self.assertNotIn("11332", json.dumps(report))

    def test_malformed_master_override_fails_closed(self):
        with self.assertRaises(PostfixConfigError):
            inspect_config(BASE, "submission/inet/smtpd_milters\n")

    def test_failure_action_accept_is_not_qualified(self):
        report = inspect_config(dict(BASE, milter_default_action="accept"), "")
        self.assertFalse(report["ok"])
        self.assertIn("milter_failure_action_not_tempfail", report["findings"])

    def test_invalid_protocol_is_not_qualified(self):
        for protocol in ("0", "7", "invalid", "-1", "9" * 5000):
            with self.subTest(protocol=protocol):
                self.assertFalse(inspect_config(dict(BASE, milter_protocol=protocol), "")["ok"])

    def test_unresolved_milter_expression_is_not_qualified(self):
        with self.assertRaises(PostfixConfigError):
            inspect_config(dict(BASE, smtpd_milters="$my_milters"), "")

    def test_missing_postconf_is_reported_not_exception(self):
        result = probe_postfix_config(executable="/no/such/postconf")
        self.assertEqual(result["status"], "unverified")
        self.assertFalse(result["ok"])

    def test_cli_opt_in_with_fake_postconf_never_sends_or_mutates(self):
        with tempfile.TemporaryDirectory() as root:
            binary = pathlib.Path(root, "postconf")
            binary.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                " '-h smtpd_milters') echo 'inet:127.0.0.1:38472' ;;\n"
                " '-h non_smtpd_milters') echo '' ;;\n"
                " '-h milter_protocol') echo '6' ;;\n"
                " '-h milter_default_action') echo 'tempfail' ;;\n"
                " '-P') exit 0 ;;\n"
                " *) exit 98 ;;\n"
                "esac\n", encoding="utf-8")
            binary.chmod(0o700)
            env = dict(os.environ, PATH=root + os.pathsep + os.environ.get("PATH", ""))
            run = subprocess.run(
                [sys.executable, str(SCRIPT), "--check-postfix-config"],
                env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            report = json.loads(run.stdout)
            self.assertEqual(report["status"], "preflight_only")
            self.assertTrue(report["postfix_config"]["ok"])
            self.assertFalse(report["smtp"]["attempted"])
            self.assertEqual(binary.stat().st_mode & 0o777, 0o700)

    def test_cli_missing_postconf_blocks_opted_in_send(self):
        with tempfile.TemporaryDirectory() as root:
            env = dict(os.environ, PATH=root)
            run = subprocess.run(
                [sys.executable, str(SCRIPT), "--check-postfix-config",
                 "--send", "--sender", "probe@example.org",
                 "--recipient", "test@example.org",
                 "--confirm-recipient", "test@example.org"],
                env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 1, run.stderr)
            report = json.loads(run.stdout)
            self.assertEqual(report["status"], "postfix_config_failed")
            self.assertFalse(report["smtp"]["attempted"])


if __name__ == "__main__":
    unittest.main()
