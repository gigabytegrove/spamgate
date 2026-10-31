#!/usr/bin/env python3
"""Hermetic native upgrade tests; never touch real systemd, ports, or mail."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name('deploy-native-worker.sh')


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'install'
        self.root.mkdir()
        (self.root / 'data').mkdir()
        self.shim = Path(self.tmp.name) / 'bin'
        self.shim.mkdir()
        self.state = Path(self.tmp.name) / 'state'
        self.state.write_text('active')
        self.log = Path(self.tmp.name) / 'actions'
        self.log.touch()
        self.old = self.root / 'spamgate-worker'
        self.new = Path(self.tmp.name) / 'new-worker'
        self.write_program(self.old, '0.6.0-beta.1')
        self.write_program(self.new, '0.6.0-beta.2')
        self.write_program(self.root / 'spamgate', '0.6.0-beta.1')
        self.launcher_hash = self.digest(self.root / 'spamgate')
        self.data_marker = self.root / 'data' / 'important.json'
        self.data_marker.write_text('{"preserve":true}')

        self.write_shim('systemctl', '''#!/bin/bash
set -eu
printf 'systemctl %s\\n' "$*" >> "$FAKE_ACTIONS"
case "$1" in
  show) printf 'path=%s/spamgate ; argv[]=%s/spamgate -data %s/data -listen 0.0.0.0:38470 ;\\n' "$FAKE_ROOT" "$FAKE_ROOT" "$FAKE_ROOT" ;;
  is-active) [[ "$(cat "$FAKE_STATE")" == active ]] ;;
  stop) echo stopped > "$FAKE_STATE" ;;
  start|restart) echo active > "$FAKE_STATE" ;;
esac
''')
        self.write_shim('curl', '''#!/bin/bash
set -eu
[[ "$(cat "$FAKE_STATE")" == active ]] || exit 7
V="$("$FAKE_ROOT/spamgate-worker" -version)"
if [[ "${FAKE_FAIL_HEALTH:-0}" == 1 && "$V" == 0.6.0-beta.2 ]]; then exit 7; fi
printf '{"status":"ok","version":"%s"}\\n' "$V"
''')
        self.write_shim('ss', '''#!/bin/sh
[ "$(cat "$FAKE_STATE")" = active ] || exit 0
printf 'LISTEN 0 4096 127.0.0.1:38472 0.0.0.0:* users:(("spamgate-worker",pid=135,fd=4))\\n'
''')
        self.write_shim('sleep', '#!/bin/sh\nexit 0\n')
        self.env = dict(os.environ, PATH=str(self.shim) + ':' + os.environ['PATH'],
                        FAKE_STATE=str(self.state), FAKE_ROOT=str(self.root),
                        FAKE_ACTIONS=str(self.log))

    def write_program(self, path, version):
        path.write_text(f'#!/bin/sh\necho {version}\n')
        path.chmod(0o755)

    def write_shim(self, name, text):
        path = self.shim / name
        path.write_text(text)
        path.chmod(0o755)

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def call(self, bad_hash=False, env_extra=None):
        env = self.env | (env_extra or {})
        return subprocess.run(['bash', str(SCRIPT), '--root', str(self.root),
                               '--worker', str(self.new), '--version', '0.6.0-beta.2',
                               '--sha256', '0'*64 if bad_hash else self.digest(self.new)],
                              env=env, text=True, capture_output=True, timeout=15)

    def assert_unchanged(self):
        self.assertEqual(self.digest(self.root / 'spamgate'), self.launcher_hash)
        self.assertEqual(self.data_marker.read_text(), '{"preserve":true}')

    def test_live_service_is_stopped_and_restarted(self):
        proc = self.call()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.digest(self.old), self.digest(self.new))
        self.assertIn('systemctl stop spamgate.service', self.log.read_text())
        self.assertIn('systemctl start spamgate.service', self.log.read_text())
        backups = list(self.root.glob('spamgate-worker.before-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(subprocess.check_output([backups[0], '-version'], text=True).strip(), '0.6.0-beta.1')
        self.assertEqual(self.state.read_text().strip(), 'active')
        self.assert_unchanged()

    def test_unhealthy_update_rolls_back_and_restarts(self):
        proc = self.call(env_extra={'FAKE_FAIL_HEALTH': '1'})
        self.assertNotEqual(proc.returncode, 0, proc.stdout)
        self.assertEqual(subprocess.check_output([self.old, '-version'], text=True).strip(), '0.6.0-beta.1')
        self.assertEqual(self.state.read_text().strip(), 'active')
        self.assertGreaterEqual(self.log.read_text().count('systemctl start spamgate.service'), 2)
        self.assert_unchanged()

    def test_same_binary_repairs_stopped_service(self):
        self.new.write_bytes(self.old.read_bytes().replace(b'0.6.0-beta.1', b'0.6.0-beta.2'))
        self.old.write_bytes(self.new.read_bytes())
        self.old.chmod(0o755)
        self.state.write_text('stopped')
        proc = self.call()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('systemctl restart spamgate.service', self.log.read_text())
        self.assertEqual(self.state.read_text().strip(), 'active')
        self.assert_unchanged()

    def test_bad_checksum_never_stops_service(self):
        proc = self.call(bad_hash=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn('systemctl stop spamgate.service', self.log.read_text())
        self.assertEqual(self.state.read_text().strip(), 'active')
        self.assert_unchanged()

    def test_wrong_launcher_unit_never_stops_unrelated_service(self):
        self.write_shim('systemctl', '''#!/bin/bash
printf 'systemctl %s\\n' "$*" >> "$FAKE_ACTIONS"
[[ "$1" != show ]] || echo 'path=/usr/local/bin/other ; argv[]=/usr/local/bin/other'
''')
        proc = self.call()
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn('systemctl stop spamgate.service', self.log.read_text())
        self.assert_unchanged()


if __name__ == '__main__':
    unittest.main()
