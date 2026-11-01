"""Opt-in, read-only Dovecot LMTP greeting/LHLO/QUIT verifier.

No MAIL, RCPT, DATA, AUTH, STARTTLS, or Postfix configuration changes.
A successful handshake is not evidence of routing, Sieve, or delivery.
"""

import os
import pathlib
import re
import socket
import stat
import time

MAX_LINE = 512
MAX_REPLY = 8192
MAX_LINES = 32
MAX_SECONDS = 8.0
KNOWN_CAPABILITIES = frozenset({
    "8BITMIME", "AUTH", "CHUNKING", "DSN", "ENHANCEDSTATUSCODES",
    "PIPELINING", "SIZE", "STARTTLS", "SMTPUTF8", "BINARYMIME",
})


class LMTPProbeError(ValueError):
    """Privacy-safe protocol or transport failure; never includes peer bytes."""


def _line(sock, deadline):
    data = bytearray()
    while len(data) <= MAX_LINE:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LMTPProbeError("LMTP reply deadline exceeded")
        try:
            sock.settimeout(min(remaining, 3.0))
            chunk = sock.recv(1)
        except (OSError, TimeoutError) as exc:
            raise LMTPProbeError("LMTP reply read failed or timed out") from exc
        if not chunk:
            raise LMTPProbeError("LMTP reply truncated")
        data.extend(chunk)
        if data.endswith(b"\r\n"):
            if any(c < 32 or c > 126 for c in data[:-2]):
                raise LMTPProbeError("LMTP reply contains non-printable bytes")
            return bytes(data[:-2])
    raise LMTPProbeError("LMTP reply line exceeds limit")


def _reply(sock, expected, deadline):
    total = 0
    lines = []
    for _ in range(MAX_LINES):
        line = _line(sock, deadline)
        total += len(line) + 2
        if total > MAX_REPLY:
            raise LMTPProbeError("LMTP reply exceeds total size limit")
        if len(line) < 4 or not line[:3].isdigit() or line[3:4] not in (b"-", b" "):
            raise LMTPProbeError("invalid LMTP reply framing")
        if int(line[:3]) != expected:
            raise LMTPProbeError("unexpected LMTP reply code")
        lines.append(line[4:])
        if line[3:4] == b" ":
            return lines
    raise LMTPProbeError("LMTP reply exceeds line-count limit")


def _verify(sock):
    deadline = time.monotonic() + MAX_SECONDS
    _reply(sock, 220, deadline)
    try:
        sock.sendall(b"LHLO spamgate-probe.invalid\r\n")
    except OSError as exc:
        raise LMTPProbeError("LMTP LHLO write failed") from exc
    lines = _reply(sock, 250, deadline)
    capabilities = set()
    for line in lines:
        token = line.split(b" ", 1)[0].upper()
        if re.fullmatch(rb"[A-Z0-9][A-Z0-9-]{0,39}", token):
            name = token.decode("ascii")
            if name in KNOWN_CAPABILITIES:
                capabilities.add(name)
    try:
        sock.sendall(b"QUIT\r\n")
    except OSError as exc:
        raise LMTPProbeError("LMTP QUIT write failed") from exc
    _reply(sock, 221, deadline)
    return {"status": "protocol_verified", "ok": True,
            "scope": "lmtp_listener_handshake_only",
            "capabilities": sorted(capabilities),
            "limitations": ["No Postfix routing, authentication, Sieve, mailbox placement or delivery was verified"]}


def probe_lmtp_listener(*, unix_socket=None, tcp_port=None):
    """Connect to one explicit local endpoint; never resolve hostnames or send mail.

    Unix socket must already exist as a real socket, not a symlink. TCP
    always uses IPv4 loopback, with no configurable remote destination.
    """
    report = {"attempted": True, "ok": False, "status": "failed",
              "scope": "lmtp_listener_handshake_only"}
    try:
        if (unix_socket is None) == (tcp_port is None):
            raise LMTPProbeError("select exactly one LMTP transport")
        if unix_socket is not None:
            if not isinstance(unix_socket, str) or not unix_socket.startswith("/") or "\x00" in unix_socket or len(os.fsencode(unix_socket)) > 107:
                raise LMTPProbeError("invalid LMTP Unix socket path")
            path = pathlib.Path(unix_socket)
            try:
                info = path.lstat()
            except OSError as exc:
                raise LMTPProbeError("LMTP Unix socket unavailable") from exc
            if not stat.S_ISSOCK(info.st_mode):
                raise LMTPProbeError("LMTP Unix endpoint is not a socket")
            report["transport"] = "unix"
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                connection.settimeout(3.0)
                connection.connect(unix_socket)
                with connection:
                    report.update(_verify(connection))
            finally:
                connection.close()
        else:
            if type(tcp_port) is not int or not 1 <= tcp_port <= 65535:
                raise LMTPProbeError("invalid LMTP TCP port")
            report["transport"] = "tcp_loopback"
            with socket.create_connection(("127.0.0.1", tcp_port), timeout=3.0) as connection:
                report.update(_verify(connection))
    except (LMTPProbeError, OSError, TimeoutError, UnicodeError) as exc:
        report["error_type"] = type(exc).__name__
        report["error"] = str(exc) if isinstance(exc, LMTPProbeError) else "LMTP connection failed"
    return report
