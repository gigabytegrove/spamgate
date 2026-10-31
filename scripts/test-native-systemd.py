#!/usr/bin/env python3
"""Hermetic regression suite for native systemd adoption; no root or MTA needed."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

MODULE = Path(__file__).with_name('install-native-systemd.py')
spec = importlib.util.spec_from_file_location('spamgate_native_systemd', MODULE)
mod = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


class FakeCommands:
    def __init__(self, *, active=False, enabled=False, fail=None):
        self.active = active
        self.enabled = enabled
        self.fail = fail
        self.calls = []

    def __call__(self, argv, *, check=True, capture_output=True, text=True):
        self.calls.append(tuple(argv))
        if argv[-1] == '-version':
            return types.SimpleNamespace(returncode=0, stdout='0.6.0-beta.1\n', stderr='')
        if argv[:3] == ['systemctl', 'is-active', '--quiet']:
            return types.SimpleNamespace(returncode=0 if self.active else 3, stdout='', stderr='')
        if argv[:3] == ['systemctl', 'is-enabled', '--quiet']:
            return types.SimpleNamespace(returncode=0 if self.enabled else 1, stdout='', stderr='')
        if self.fail is not None and tuple(argv[:len(self.fail)]) == self.fail:
            self.fail = None
            if check:
                raise subprocess.CalledProcessError(1, argv, stderr='injected failure')
            return types.SimpleNamespace(returncode=1, stdout='', stderr='injected failure')
        if argv[:2] == ['systemctl', 'enable']:
            self.enabled = True
        if argv[:2] == ['systemctl', 'disable']:
            self.enabled = False
        if argv[:2] in (['systemctl', 'start'], ['systemctl', 'restart']):
            self.active = True
        if argv[:2] == ['systemctl', 'stop']:
            self.active = False
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')


class NativeSystemdTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.install = self.root / 'opt' / 'spamgate'
        self.unit_dir = self.root / 'etc' / 'systemd' / 'system'
        self.install.mkdir(parents=True)
        self.unit_dir.mkdir(parents=True)
        (self.install / 'data').mkdir(mode=0o700)
        for name in ('spamgate', 'spamgate-worker'):
            executable = self.install / name
            executable.write_text('#!/bin/sh\nexit 0\n')
            executable.chmod(0o755)
        self.commands = FakeCommands()
        self.manual = []
        self.stopped = []
        self.restored = []
        self.probes = []
        self.http = lambda version: self.probes.append(('http', version))
        self.milter = lambda: self.probes.append(('milter', mod.MILTER))
        self.installer = mod.Installer(
            self.install, self.unit_dir, runner=self.commands,
            processes=lambda _: self.manual,
            stopper=lambda proc: self.stopped.append(proc.pid),
            restorer=lambda proc, *_: self.restored.append(proc.pid),
            http_probe=lambda version: self.http(version),
            milter_probe=lambda: self.milter(),
        )
        self.root_patch = mock.patch.object(mod.os, 'geteuid', return_value=0)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_preview_is_read_only_and_explicit(self):
        before = list(self.unit_dir.rglob('*'))
        output = self.installer.preview()
        self.assertIn('PREVIEW ONLY', output)
        self.assertIn('Apply explicitly with --apply', output)
        self.assertEqual(before, list(self.unit_dir.rglob('*')))
        self.assertFalse(self.commands.active)

    def test_clean_install_creates_supervised_service_and_milter(self):
        result = self.installer.apply()
        self.assertIn('PASS:', result)
        self.assertTrue(self.commands.active)
        self.assertTrue(self.commands.enabled)
        unit = self.installer.unit.read_text()
        self.assertIn(f'ExecStart={self.install}/spamgate -data {self.install}/data -listen 0.0.0.0:38470', unit)
        self.assertIn('Restart=always', unit)
        self.assertIn('KillMode=control-group', unit)
        self.assertIn('ProtectSystem=full', unit)
        self.assertIn('SPAMGATE_MILTER_LISTEN=127.0.0.1:38472', self.installer.dropin.read_text())
        self.assertEqual(self.probes, [('http', '0.6.0-beta.1'), ('milter', mod.MILTER)])
        self.assertEqual(list((self.install / 'data').iterdir()), [])
        self.assertNotIn(('systemctl', 'restart', 'postfix'), self.commands.calls)

    def test_existing_unit_preserved_and_restart_only_spamgate(self):
        old = self.installer.unit_text() + b'\n# hosting panel ownership\n'
        self.installer.unit.write_bytes(old)
        self.installer.dropin.parent.mkdir()
        self.installer.dropin.write_text('[Service]\nEnvironment="OLD=yes"\n')
        self.commands.active = True
        self.commands.enabled = True
        self.installer.apply()
        self.assertEqual(self.installer.unit.read_bytes(), old)
        self.assertIn(('systemctl', 'restart', 'spamgate.service'), self.commands.calls)
        self.assertFalse(self.stopped)

    def test_unexpected_service_execstart_refused(self):
        self.installer.unit.write_text('[Service]\nExecStart=/usr/bin/other\n')
        with self.assertRaisesRegex(RuntimeError, 'different ExecStart'):
            self.installer.apply()
        self.assertEqual(self.installer.unit.read_text(), '[Service]\nExecStart=/usr/bin/other\n')

    def test_manual_process_requires_explicit_adoption(self):
        self.manual = [mod.ManualProcess(1001, ['./spamgate', '-data', str(self.install / 'data'), '-listen', mod.WEB], {}, str(self.install))]
        with self.assertRaisesRegex(RuntimeError, 'adopt-manual'):
            self.installer.apply()
        self.assertFalse(self.stopped)
        self.assertFalse(self.installer.unit.exists())

    def test_manual_adoption_stops_only_expected_launcher(self):
        self.manual = [mod.ManualProcess(1001, ['./spamgate', '-data', str(self.install / 'data'), '-listen', mod.WEB], {}, str(self.install))]
        self.installer.apply(adopt_manual=True)
        self.assertEqual(self.stopped, [1001])
        self.assertEqual(self.restored, [])
        self.assertTrue(self.commands.active)

    def test_manual_adoption_refuses_different_data_directory(self):
        self.manual = [mod.ManualProcess(1004, ['./spamgate', '-data', '/elsewhere', '-listen', mod.WEB], {}, str(self.install))]
        with self.assertRaisesRegex(RuntimeError, 'arguments differ'):
            self.installer.apply(adopt_manual=True)
        self.assertFalse(self.stopped)

    def test_dropin_write_failure_rolls_back_new_unit(self):
        real_write = mod.atomic_write
        def fail_dropin(path, content):
            if path == self.installer.dropin:
                raise OSError('injected drop-in disk failure')
            return real_write(path, content)
        with mock.patch.object(mod, 'atomic_write', side_effect=fail_dropin):
            with self.assertRaisesRegex(RuntimeError, 'configuration restored'):
                self.installer.apply()
        self.assertFalse(self.installer.unit.exists())
        self.assertFalse(self.installer.dropin.exists())
        self.assertFalse(self.commands.active)

    def test_new_service_rolls_back_on_health_failure(self):
        self.http = lambda _: (_ for _ in ()).throw(RuntimeError('HTTP failed'))
        with self.assertRaisesRegex(RuntimeError, 'configuration restored'):
            self.installer.apply()
        self.assertFalse(self.installer.unit.exists())
        self.assertFalse(self.installer.dropin.exists())
        self.assertFalse(self.commands.active)
        self.assertFalse(self.commands.enabled)

    def test_existing_service_rolls_back_previous_dropin(self):
        original = self.installer.unit_text()
        self.installer.unit.write_bytes(original)
        self.installer.dropin.parent.mkdir()
        self.installer.dropin.write_text('[Service]\nEnvironment="SPAMGATE_TEST=1"\n')
        self.commands.active = True
        self.commands.enabled = True
        self.milter = lambda: (_ for _ in ()).throw(RuntimeError('milter failed'))
        with self.assertRaisesRegex(RuntimeError, 'milter failed'):
            self.installer.apply()
        self.assertEqual(self.installer.unit.read_bytes(), original)
        self.assertEqual(self.installer.dropin.read_text(), '[Service]\nEnvironment="SPAMGATE_TEST=1"\n')
        self.assertTrue(self.commands.active)
        self.assertTrue(self.commands.enabled)

    def test_manual_adoption_failure_restores_original_launcher(self):
        self.manual = [mod.ManualProcess(2002, ['./spamgate', '-data', str(self.install / 'data'), '-listen', mod.WEB], {}, str(self.install))]
        self.milter = lambda: (_ for _ in ()).throw(RuntimeError('Milter failed'))
        with self.assertRaisesRegex(RuntimeError, 'Milter failed'):
            self.installer.apply(adopt_manual=True)
        self.assertEqual(self.stopped, [2002])
        self.assertEqual(self.restored, [2002])
        self.assertFalse(self.installer.unit.exists())

    def test_systemd_verify_failure_rolls_back_without_stopping_manual(self):
        self.manual = [mod.ManualProcess(3003, ['./spamgate', '-data', str(self.install / 'data'), '-listen', mod.WEB], {}, str(self.install))]
        self.commands.fail = ('systemd-analyze', 'verify')
        with self.assertRaisesRegex(RuntimeError, 'configuration restored'):
            self.installer.apply(adopt_manual=True)
        self.assertFalse(self.stopped)
        self.assertFalse(self.installer.unit.exists())

    def test_symlinked_worker_refused(self):
        worker = self.install / 'spamgate-worker'
        worker.unlink()
        worker.symlink_to('/bin/true')
        with self.assertRaisesRegex(RuntimeError, 'unsafe executable'):
            self.installer.apply()
        self.assertFalse(self.installer.unit.exists())

    def test_unprivileged_apply_refused(self):
        with mock.patch.object(mod.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(RuntimeError, 'requires root'):
                self.installer.apply()
        self.assertFalse(self.installer.unit.exists())


if __name__ == '__main__':
    unittest.main()
