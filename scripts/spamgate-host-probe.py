#!/usr/bin/env python3
"""Non-destructive SpamGate host preflight and opt-in SMTP test harness.

Default mode never transmits mail. Sending requires --send, --recipient and
--confirm-recipient to match exactly; target must be loopback unless --allow-remote.
The harness never edits Postfix, Dovecot, SpamGate configuration or spool files.
"""
import argparse
import http.client
import json
import os
import pathlib
import re
import socket
import smtplib
import ipaddress
import ssl
import sys
import uuid
from email.message import EmailMessage

MAX_MESSAGE_BYTES = 128 * 1024

def address(value):
    if not value or any(c in value for c in "\r\n\x00<>") or value.count("@") != 1:
        raise argparse.ArgumentTypeError("provide one plain mailbox address")
    local, domain = value.rsplit("@", 1)
    if not local or not domain or any(c.isspace() for c in value):
        raise argparse.ArgumentTypeError("invalid mailbox")
    return value

def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=25)
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--recipient", type=address)
    p.add_argument("--confirm-recipient", type=address)
    p.add_argument("--sender", type=address, help="explicit sender authorized for the test mailbox")
    p.add_argument("--send", action="store_true", help="explicitly enable SMTP submission")
    p.add_argument("--allow-remote", action="store_true", help="explicitly permit non-loopback target")
    p.add_argument("--starttls", action="store_true", help="require STARTTLS with verified certificate")
    p.add_argument("--category-marker", help="optional harmless SGTUBE marker, test mailbox only")
    p.add_argument("--output", help="write JSON report, exclusive create")
    p.add_argument("--check-services", action="store_true", help="opt-in read-only loopback HTTP health and Milter TCP checks")
    p.add_argument("--health-port", type=int, default=38470, help="loopback health port (default 38470)")
    p.add_argument("--milter-port", type=int, default=38472, help="loopback Milter TCP port (default 38472)")
    p.add_argument("--expect-version", help="require the /healthz worker version to match exactly")
    a = p.parse_args(argv)
    if not all(1 <= port <= 65535 for port in (a.port, a.health_port, a.milter_port)) or not 0 < a.timeout <= 120:
        p.error("ports must be 1..65535 and timeout 0..120 seconds")
    if a.expect_version and (not a.check_services or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}", a.expect_version)):
        p.error("--expect-version requires --check-services and a safe version token")
    if a.send and (not a.recipient or a.recipient != a.confirm_recipient):
        p.error("--send requires matching --recipient and --confirm-recipient")
    if a.send and not a.sender:
        p.error("--send requires an explicit --sender")
    if a.category_marker and (not a.send or len(a.category_marker) > 2048 or any(x in a.category_marker for x in "\r\n")):
        p.error("marker requires --send and a single-line marker <=2048 characters")
    if a.send:
        try:
            target = ipaddress.ip_address(a.host)
        except ValueError:
            p.error("SMTP host must be an IP literal to prevent DNS rebinding")
        if not target.is_loopback and not a.allow_remote:
            p.error("non-loopback SMTP target requires --allow-remote")
    return a

def preflight():
    paths = {
        "launcher": "/opt/spamgate/spamgate",
        "worker": "/opt/spamgate/spamgate-worker",
        "data": "/opt/spamgate/data",
    }
    results = {}
    for key, value in paths.items():
        p = pathlib.Path(value)
        try:
            st = p.lstat()
            results[key] = {"exists": True, "symlink": p.is_symlink(),
                            "directory": p.is_dir(), "mode": oct(st.st_mode & 0o777)}
        except FileNotFoundError:
            results[key] = {"exists": False}
        except OSError as exc:
            results[key] = {"error": str(exc)}
    return results

def probe_services(a):
    """Opt-in loopback checks. No HTTP redirects, proxy, SMTP, or Milter commands.

    A TCP accept on the Milter port proves only that something is listening;
    it does not prove Milter protocol negotiation or mail disposition.
    """
    result = {
        "attempted": True,
        "health": {"status": "failed", "target": f"127.0.0.1:{a.health_port}"},
        "milter": {"status": "failed", "target": f"127.0.0.1:{a.milter_port}",
                   "protocol_verified": False},
    }
    connection = http.client.HTTPConnection("127.0.0.1", a.health_port, timeout=a.timeout)
    try:
        connection.request("GET", "/healthz",
                           headers={"Host": "127.0.0.1", "Accept": "application/json",
                                    "Connection": "close"})
        response = connection.getresponse()
        result["health"]["http_status"] = response.status
        raw = response.read(4097)
        if len(raw) > 4096:
            raise ValueError("health response exceeds 4096-byte limit")
        if response.status != 200:
            raise ValueError(f"health endpoint returned HTTP {response.status}")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("status") != "ok":
            raise ValueError("health response did not report status=ok")
        version = payload.get("version")
        if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}", version):
            raise ValueError("health response version is missing or invalid")
        result["health"]["version"] = version
        if a.expect_version and version != a.expect_version:
            raise ValueError("health version does not match --expect-version")
        result["health"]["status"] = "ok"
    except (OSError, ValueError, http.client.HTTPException) as exc:
        result["health"]["error_type"] = type(exc).__name__
        result["health"]["error"] = str(exc)[:240]
    finally:
        connection.close()

    try:
        with socket.create_connection(("127.0.0.1", a.milter_port), timeout=a.timeout):
            result["milter"]["status"] = "tcp_listening"
    except OSError as exc:
        result["milter"]["error_type"] = type(exc).__name__
        result["milter"]["error"] = str(exc)[:240]
    result["ok"] = (result["health"]["status"] == "ok" and
                    result["milter"]["status"] == "tcp_listening")
    return result


def make_message(a, run_id):
    msg = EmailMessage()
    msg["From"] = a.sender
    msg["To"] = a.recipient
    msg["Subject"] = "SpamGate controlled probe " + run_id
    msg["X-SpamGate-Probe-ID"] = run_id
    msg["Date"] = __import__("email.utils", fromlist=["formatdate"]).formatdate(localtime=False)
    body = "Controlled mail delivery verification. No external links or attachments.\n"
    if a.category_marker:
        body += "\nSynthetic test marker (NOT real spam): " + a.category_marker + "\n"
    msg.set_content(body)
    if len(msg.as_bytes()) > MAX_MESSAGE_BYTES:
        raise ValueError("message exceeds size cap")
    return msg

def run(a):
    report = {"schema": 1, "run_id": uuid.uuid4().hex,
              "timestamp_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
              "host": a.host, "port": a.port, "send_requested": a.send,
              "preflight": preflight(), "services": {"attempted": False},
              "smtp": {"attempted": False},
              "limitations": ["SMTP 250 is not proof of mailbox delivery",
                              "Synthetic marker results do not measure real-world classifier accuracy",
                              "Read-only preflight cannot establish production safety",
                              "Milter TCP acceptance does not verify protocol negotiation or message disposition"]}
    if a.check_services:
        report["services"] = probe_services(a)
        if not report["services"]["ok"]:
            report["status"] = "service_probe_failed"
            return report
    if not a.send:
        report["status"] = "preflight_only"
        return report
    report["smtp"]["attempted"] = True
    try:
        with smtplib.SMTP(a.host, a.port, timeout=a.timeout, local_hostname="spamgate-probe.invalid") as smtp:
            smtp.ehlo()
            report["smtp"]["ehlo_extensions"] = sorted(smtp.esmtp_features)
            if a.starttls:
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                report["smtp"]["starttls_verified"] = True
            msg = make_message(a, report["run_id"])
            refused = smtp.send_message(msg, from_addr=a.sender, to_addrs=[a.recipient])
            report["smtp"]["recipient_refusals"] = {k: [v[0], v[1].decode("utf-8", "replace") if isinstance(v[1], bytes) else str(v[1])] for k, v in refused.items()}
            report["status"] = "smtp_accepted" if not refused else "recipient_refused"
    except (smtplib.SMTPException, OSError, TimeoutError, ssl.SSLError) as exc:
        report["status"] = "smtp_failed"
        report["smtp"]["error_type"] = type(exc).__name__
        report["smtp"]["error"] = str(exc)[:500]
    return report

def main(argv=None):
    a = parse_args(argv)
    report = run(a)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if a.output:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(a.output, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
    sys.stdout.write(encoded)
    return 0 if report["status"] in ("preflight_only", "smtp_accepted") else 1

if __name__ == "__main__":
    raise SystemExit(main())
