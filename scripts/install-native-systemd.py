#!/usr/bin/env python3
"""Explicit, transactional systemd adoption for the native two-process SpamGate.

Preview is the default. --apply changes SpamGate's systemd unit only, never Postfix.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?$")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
MILTER = "127.0.0.1:38472"
WEB = "0.0.0.0:38470"


@dataclasses.dataclass
class ManualProcess:
    pid: int
    argv: list[str]
    environment: dict[str, str]
    cwd: str


def find_manual(launcher: Path) -> list[ManualProcess]:
    found = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        try:
            if (directory / 'exe').resolve() != launcher.resolve():
                continue
            args = (directory / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
            if not args:
                continue
            argv = [os.fsdecode(a) for a in args]
            env = {}
            for part in (directory / 'environ').read_bytes().rstrip(b'\0').split(b'\0'):
                if b'=' in part:
                    k, v = part.split(b'=', 1)
                    env[os.fsdecode(k)] = os.fsdecode(v)
            found.append(ManualProcess(int(directory.name), argv, env,
                                       os.readlink(directory / 'cwd')))
        except (OSError, PermissionError, ProcessLookupError):
            continue
    return found


def stop_manual(proc: ManualProcess) -> None:
    os.kill(proc.pid, signal.SIGTERM)
    for _ in range(100):
        try:
            stat = Path(f'/proc/{proc.pid}/stat').read_text()
            if stat.rsplit(')', 1)[-1].split()[0] == 'Z':
                return
            os.kill(proc.pid, 0)
        except ProcessLookupError:
            return
        except FileNotFoundError:
            return
        time.sleep(0.2)
    raise RuntimeError(f'manual launcher PID {proc.pid} did not exit after SIGTERM; refusing SIGKILL')


def restore_manual(proc: ManualProcess, launcher: Path, data: Path) -> None:
    # Preserve original environment without logging secrets. The executable is
    # pinned to the already validated installation, not argv[0] from /proc.
    log_path = data / 'manual-recovery.log'
    fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'ab', buffering=0) as log:
        subprocess.Popen([str(launcher), *proc.argv[1:]], cwd=proc.cwd,
                         env=proc.environment, stdin=subprocess.DEVNULL,
                         stdout=log, stderr=log, start_new_session=True)


def wait_ports_free() -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        busy = False
        for port in (38470, 38472):
            with socket.socket() as sock:
                sock.settimeout(0.2)
                if sock.connect_ex(('127.0.0.1', port)) == 0:
                    busy = True
        if not busy:
            return
        time.sleep(0.2)
    raise RuntimeError('ports 38470/38472 remained occupied after stopping manual launcher')


def http_health(expected: str) -> None:
    deadline = time.monotonic() + 20
    last = 'no response'
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen('http://127.0.0.1:38470/healthz', timeout=2) as response:
                payload = json.load(response)
            if payload.get('status') == 'ok' and payload.get('version') == expected:
                return
            last = f'unexpected health payload: {payload!r}'
        except (OSError, ValueError) as exc:
            last = str(exc)
        time.sleep(0.25)
    raise RuntimeError(f'HTTP health/version did not verify: {last}')


def milter_health() -> None:
    result = subprocess.run(['ss', '-ltnp', '( sport = :38472 )'],
                            text=True, capture_output=True, check=True)
    if not any('127.0.0.1:38472' in line and 'spamgate-worker' in line
               for line in result.stdout.splitlines()):
        raise RuntimeError('Milter is not owned by spamgate-worker on 127.0.0.1:38472')


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.spamgate-unit-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class Installer:
    def __init__(self, install: Path, unit_dir: Path, *, runner=subprocess.run,
                 processes=find_manual, stopper=stop_manual, restorer=restore_manual,
                 http_probe=http_health, milter_probe=milter_health):
        self.install = install
        self.unit_dir = unit_dir
        self.launcher = install / 'spamgate'
        self.worker = install / 'spamgate-worker'
        self.data = install / 'data'
        self.unit = unit_dir / 'spamgate.service'
        self.dropin = unit_dir / 'spamgate.service.d' / '10-milter.conf'
        self.runner = runner
        self.processes = processes
        self.stopper = stopper
        self.restorer = restorer
        self.http_probe = http_probe
        self.milter_probe = milter_probe

    def call(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return self.runner(list(args), check=check, capture_output=True, text=True)

    def preflight(self) -> tuple[str, str]:
        if not SAFE_PATH.fullmatch(str(self.install)) or not SAFE_PATH.fullmatch(str(self.unit_dir)):
            raise RuntimeError('install and unit directories must be absolute, shell-safe paths')
        if self.install.resolve() != self.install or self.unit_dir.resolve() != self.unit_dir:
            raise RuntimeError('symlinked installation or unit directory refused')
        for executable in (self.launcher, self.worker):
            if executable.is_symlink() or not executable.is_file() or not os.access(executable, os.X_OK):
                raise RuntimeError(f'missing or unsafe executable: {executable}')
        if self.data.is_symlink() or not self.data.is_dir():
            raise RuntimeError(f'persistent data directory missing or symlinked: {self.data}')
        versions = []
        for executable in (self.launcher, self.worker):
            result = self.call(str(executable), '-version')
            version = result.stdout.strip()
            if not VERSION.fullmatch(version):
                raise RuntimeError(f'{executable} reported invalid version: {version!r}')
            versions.append(version)
        if self.unit.is_symlink() or self.dropin.is_symlink():
            raise RuntimeError('refusing to replace symlinked systemd configuration')
        if self.unit.exists():
            text = self.unit.read_text()
            if not re.search(r'(?m)^ExecStart=' + re.escape(str(self.launcher)) + r'(?:[ \t]|$)', text):
                raise RuntimeError('existing service has a different ExecStart; refusing takeover')
        return versions[0], versions[1]

    def unit_text(self) -> bytes:
        return (f'''[Unit]
Description=SpamGate Native Mail Filtering Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory={self.install}
ExecStart={self.launcher} -data {self.data} -listen {WEB}
Restart=always
RestartSec=5s
TimeoutStopSec=30s
KillMode=control-group
LimitNOFILE=65535
UMask=0077
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
ReadWritePaths={self.install}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=spamgate

[Install]
WantedBy=multi-user.target
''').encode()

    @staticmethod
    def dropin_text() -> bytes:
        return (f'''[Service]
Environment="SPAMGATE_MILTER_LISTEN={MILTER}"
Environment="SPAMGATE_MILTER_TRUSTED_CIDRS=127.0.0.1/32"
''').encode()

    def preview(self) -> str:
        launcher_version, worker_version = self.preflight()
        return (f'PREVIEW ONLY: launcher {launcher_version}; worker {worker_version}\n'
                f'Unit: {self.unit} ({"preserve existing" if self.unit.exists() else "create"})\n'
                f'Milter drop-in: {self.dropin} (create/replace)\n'
                f'Web: {WEB}; Milter: {MILTER}; trusted: 127.0.0.1/32\n'
                'No Postfix/Dovecot configuration or data will be modified.\n'
                'Apply explicitly with --apply. Use --adopt-manual only for an existing foreground launcher.')

    def apply(self, *, adopt_manual: bool = False) -> str:
        if os.geteuid() != 0:
            raise RuntimeError('--apply requires root')
        _, worker_version = self.preflight()
        was_active = self.call('systemctl', 'is-active', '--quiet', 'spamgate.service', check=False).returncode == 0
        was_enabled = self.call('systemctl', 'is-enabled', '--quiet', 'spamgate.service', check=False).returncode == 0
        manual = [] if was_active else self.processes(self.launcher)
        if manual and (not adopt_manual or len(manual) != 1):
            raise RuntimeError('manual SpamGate launcher detected; use --adopt-manual explicitly (exactly one launcher required)')
        if manual and manual[0].argv[1:] != ['-data', str(self.data), '-listen', WEB]:
            raise RuntimeError('manual launcher arguments differ from native service contract; refusing adoption')
        if not was_active and not manual:
            for port in (38470, 38472):
                with socket.socket() as sock:
                    sock.settimeout(0.2)
                    if sock.connect_ex(('127.0.0.1', port)) == 0:
                        raise RuntimeError(f'port {port} occupied by another service; refusing takeover')
        original_unit = self.unit.read_bytes() if self.unit.exists() else None
        original_dropin = self.dropin.read_bytes() if self.dropin.exists() else None
        changed = False
        stopped_manual = False
        try:
            if original_unit is None:
                atomic_write(self.unit, self.unit_text())
                changed = True
            # The drop-in write can fail after creating/replacing a file.
            # Mark rollback required before attempting it.
            changed = True
            atomic_write(self.dropin, self.dropin_text())
            self.call('systemd-analyze', 'verify', str(self.unit))
            self.call('systemctl', 'daemon-reload')
            if manual:
                self.stopper(manual[0])
                stopped_manual = True
                wait_ports_free()
            self.call('systemctl', 'enable', 'spamgate.service')
            self.call('systemctl', 'restart' if was_active else 'start', 'spamgate.service')
            self.http_probe(worker_version)
            self.milter_probe()
            if self.call('systemctl', 'is-active', '--quiet', 'spamgate.service', check=False).returncode != 0:
                raise RuntimeError('systemd service stopped after health checks')
            return (f'PASS: systemd enabled and active; HTTP {worker_version}; '
                    f'Milter {MILTER}; original data untouched')
        except Exception as failure:
            if changed:
                # Stop new service before restoring old configuration. The MTA
                # remains untouched throughout, including on rollback.
                self.call('systemctl', 'stop', 'spamgate.service', check=False)
                for path, original in ((self.unit, original_unit), (self.dropin, original_dropin)):
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write(path, original)
                self.call('systemctl', 'daemon-reload', check=False)
                if not was_enabled:
                    self.call('systemctl', 'disable', 'spamgate.service', check=False)
                if was_active:
                    self.call('systemctl', 'start', 'spamgate.service', check=False)
                elif stopped_manual:
                    self.restorer(manual[0], self.launcher, self.data)
            raise RuntimeError(f'install failed; systemd configuration restored: {failure}') from failure


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install-dir', type=Path, default=Path('/opt/spamgate'))
    parser.add_argument('--unit-dir', type=Path, default=Path('/etc/systemd/system'))
    parser.add_argument('--apply', action='store_true', help='explicitly install/modify and start service')
    parser.add_argument('--adopt-manual', action='store_true', help='stop exactly one matching manual launcher during --apply')
    args = parser.parse_args()
    installer = Installer(args.install_dir, args.unit_dir)
    try:
        if args.adopt_manual and not args.apply:
            parser.error('--adopt-manual requires --apply')
        print(installer.apply(adopt_manual=args.adopt_manual) if args.apply else installer.preview())
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
