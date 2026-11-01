"""Read-only Dovecot LDA/LMTP Sieve configuration and file-integrity probe.

This verifies a *configuration snapshot*, never an active mailbox disposition.
It does not run sievec, change files, reload services or submit mail.
"""
import hashlib
import os
import pathlib
import re
import shutil
import stat
from spamgate_bounded_command import CommandProbeError, capture_command

EXPECTED_RULE = "/etc/dovecot/sieve/spamgate-junk.sieve"
EXPECTED_FILES = (
    "/etc/dovecot/sieve/spamgate-junk.sieve",
    "/etc/dovecot/sieve/spamgate-junk.svbin",
    "/etc/dovecot/conf.d/99-spamgate-junk.conf",
)
MANIFEST = "/etc/dovecot/conf.d/99-spamgate-junk.sha256"
MAX_CONFIG = 65536
MAX_FILE = 4 * 1024 * 1024


class DovecotProbeError(ValueError):
    """A safe diagnostic failure without sensitive configuration values."""


def _doveconf(executable=None):
    binary = executable or shutil.which("doveconf")
    if not binary:
        raise DovecotProbeError("doveconf executable not found")
    try:
        stdout, stderr, exit_code = capture_command(
            [binary, "-n"], timeout=5, max_bytes=MAX_CONFIG)
    except CommandProbeError as exc:
        raise DovecotProbeError("doveconf " + str(exc)) from exc
    if exit_code:
        raise DovecotProbeError("doveconf configuration validation failed")
    if stderr.strip():
        raise DovecotProbeError("doveconf emitted diagnostics")
    try:
        raw = stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise DovecotProbeError("doveconf output is not UTF-8") from exc
    if "\x00" in raw:
        raise DovecotProbeError("doveconf output contains NUL")
    return raw


def parse_doveconf(raw):
    """Parse relevant top-level scopes, ignoring unrelated nested service blocks.

    Reject ambiguous repeated scopes/keys and unbalanced syntax rather than
    accidentally treating LMTP or an unrelated plugin as LDA evidence.
    """
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_CONFIG:
        raise DovecotProbeError("invalid or oversized configuration snapshot")
    stack = []
    scopes = {}
    for line in raw.splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        if item == "}":
            if not stack:
                raise DovecotProbeError("unbalanced Dovecot configuration")
            stack.pop()
            continue
        if item.endswith("{") and "=" not in item:
            name = item[:-1].strip()
            if not name or "}" in name or "{" in name:
                raise DovecotProbeError("invalid Dovecot section")
            stack.append(name)
            if len(stack) > 16:
                raise DovecotProbeError("Dovecot section nesting exceeds limit")
            scope = tuple(stack)
            if scope in (("protocol lda",), ("protocol lmtp",), ("plugin",)):
                if scope in scopes:
                    raise DovecotProbeError("duplicate relevant Dovecot section")
                scopes[scope] = {}
            continue
        if "=" not in item:
            raise DovecotProbeError("unparseable Dovecot configuration line")
        key, value = (part.strip() for part in item.split("=", 1))
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
            raise DovecotProbeError("invalid Dovecot setting name")
        scope = tuple(stack)
        if scope in (("protocol lda",), ("protocol lmtp",), ("plugin",)):
            settings = scopes[scope]
            if key in settings:
                raise DovecotProbeError("duplicate relevant Dovecot setting")
            settings[key] = value
    if stack:
        raise DovecotProbeError("unterminated Dovecot configuration section")
    return scopes


def inspect_config(raw, delivery_path="lda"):
    """Check only the explicitly selected Dovecot delivery protocol.

    A configured LDA plugin does not qualify LMTP, or vice versa. This
    deliberately does not infer which transport Postfix actually uses.
    """
    if delivery_path not in ("lda", "lmtp"):
        raise DovecotProbeError("unsupported Dovecot delivery path")
    scopes = parse_doveconf(raw)
    protocol = scopes.get(("protocol " + delivery_path,), {})
    plugin = scopes.get(("plugin",), {})
    tokens = protocol.get("mail_plugins", "").strip().strip("\"'").split()
    rule = plugin.get("sieve_before", "").strip().strip("\"'")
    findings = []
    if "sieve" not in tokens:
        findings.append(delivery_path + "_sieve_plugin_not_explicitly_enabled")
    if rule != EXPECTED_RULE:
        findings.append("spamgate_sieve_before_not_configured")
    return findings


def _safe_read(path, limit):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            raise DovecotProbeError("unsafe Sieve file type or permissions")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            actual = os.fstat(handle.fileno())
            if (not stat.S_ISREG(actual.st_mode) or actual.st_mode & 0o022
                    or actual.st_size > limit or (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino)):
                raise DovecotProbeError("unsafe or changed Sieve file")
            data = handle.read(limit + 1)
            if len(data) > limit or os.fstat(handle.fileno()).st_size != actual.st_size:
                raise DovecotProbeError("Sieve file exceeded limit or changed")
            return data
    except (OSError, ValueError) as exc:
        if isinstance(exc, DovecotProbeError):
            raise
        raise DovecotProbeError("Sieve file unavailable or unsafe") from exc


def inspect_installed_files(root=pathlib.Path("/etc/dovecot")):
    root = pathlib.Path(root)
    for folder in (root, root / "sieve", root / "conf.d"):
        try:
            info = folder.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise DovecotProbeError("unsafe Dovecot configuration directory")
        except OSError as exc:
            raise DovecotProbeError("Dovecot configuration directory unavailable") from exc
    digest_map = {}
    for absolute in EXPECTED_FILES:
        relative = pathlib.PurePosixPath(absolute).relative_to("/etc/dovecot")
        data = _safe_read(root / relative, MAX_FILE)
        if not data:
            raise DovecotProbeError("empty installed Sieve file")
        digest_map[absolute] = hashlib.sha256(data).hexdigest()
    raw = _safe_read(root / pathlib.PurePosixPath(MANIFEST).relative_to("/etc/dovecot"), 4096)
    recorded = {}
    for line in raw.decode("ascii", "strict").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64}) [ *](/etc/dovecot/[A-Za-z0-9/._-]+)", line)
        if not match or match.group(2) in recorded:
            raise DovecotProbeError("invalid or ambiguous Sieve manifest")
        recorded[match.group(2)] = match.group(1)
    if recorded != digest_map:
        raise DovecotProbeError("installed Sieve file checksum mismatch")
    return True


def probe_dovecot_sieve(executable=None, root=pathlib.Path("/etc/dovecot"),
                        delivery_path="lda"):
    """Return path-specific privacy-safe evidence, never a routing claim."""
    # Keep the report bounded even for invalid direct library callers.
    selected = delivery_path if delivery_path in ("lda", "lmtp") else None
    scope = "dovecot_" + (selected or "unknown") + "_configuration_only"
    try:
        if selected is None:
            raise DovecotProbeError("unsupported Dovecot delivery path")
        findings = inspect_config(_doveconf(executable), delivery_path=selected)
        if findings:
            return {"attempted": True, "ok": False, "status": "requires_review",
                    "delivery_path": selected, "scope": scope, "findings": findings}
        inspect_installed_files(root)
        return {"attempted": True, "ok": True,
                "status": selected + "_sieve_config_checked",
                "delivery_path": selected, "scope": scope, "findings": [],
                "limitations": [
                    "doveconf -n is a configuration snapshot, not evidence of an active reload",
                    "only the selected delivery path is checked; Postfix routing and ISPConfig persistence are not certified",
                    "file checksums do not prove Sieve execution, final mailbox placement or correct recipient ownership",
                ]}
    except (DovecotProbeError, UnicodeError) as exc:
        return {"attempted": True, "ok": False, "status": "unverified",
                "delivery_path": selected, "scope": scope,
                "error": str(exc), "findings": ["dovecot_sieve_unverified"]}
