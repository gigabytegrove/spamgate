"""Read-only, opt-in audit of the effective Postfix SMTP Milter configuration.

This is configuration evidence, not proof of Postfix action enforcement.
Never invokes postconf -e, postfix reload, postsuper, or SMTP submission.
"""
import re
import shutil
import subprocess

EXPECTED_MILTER = "inet:127.0.0.1:38472"
PARAMETERS = ("smtpd_milters", "non_smtpd_milters", "milter_protocol",
              "milter_default_action")
WATCHED_OVERRIDES = frozenset(PARAMETERS + ("smtpd_milter_maps",))
MAX_OUTPUT = 65536


class PostfixConfigError(ValueError):
    """A bounded, non-sensitive configuration diagnostic failure."""


def _postconf(arguments, executable=None):
    binary = executable or shutil.which("postconf")
    if not binary:
        raise PostfixConfigError("postconf executable not found")
    try:
        completed = subprocess.run(
            [binary, *arguments], capture_output=True, timeout=5, check=False)
    except subprocess.TimeoutExpired as exc:
        raise PostfixConfigError("postconf read timed out") from exc
    except OSError as exc:
        raise PostfixConfigError("postconf could not be executed") from exc
    if (len(completed.stdout) > MAX_OUTPUT or
            len(completed.stderr) > MAX_OUTPUT):
        raise PostfixConfigError("postconf output exceeds bounded limit")
    if completed.returncode:
        raise PostfixConfigError("postconf read failed")
    if completed.stderr.strip():
        raise PostfixConfigError("postconf emitted configuration diagnostics")
    try:
        value = completed.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise PostfixConfigError("postconf returned invalid UTF-8") from exc
    if "\x00" in value:
        raise PostfixConfigError("postconf returned a NUL byte")
    return value


def _value(raw):
    if not isinstance(raw, str):
        raise PostfixConfigError("invalid postconf value type")
    lines = raw.splitlines()
    if len(lines) > 1:
        raise PostfixConfigError("unexpected multiline postconf value")
    return (lines[0] if lines else "").strip()


def _milters(raw):
    value = _value(raw)
    # A variable reference or unusual Postfix expression must be resolved by
    # the operator; do not assert an endpoint from partially expanded text.
    if "$" in value or "{" in value or "}" in value:
        raise PostfixConfigError("unresolved Milter configuration expression")
    return [token for token in re.split(r"[,\s]+", value) if token]


def _overrides(raw):
    found = set()
    for line in raw.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"\s*([^\s=]+)\s*=\s*(.*)", line)
        if not match:
            raise PostfixConfigError("unparseable master.cf override")
        key = match.group(1)
        parts = key.split("/")
        if len(parts) != 3 or not all(parts):
            raise PostfixConfigError("unparseable master.cf override key")
        if parts[-1] in WATCHED_OVERRIDES:
            found.add(parts[-1])
    return sorted(found)


def inspect_config(values, master_overrides):
    """Pure, conservative assessment; never includes raw Postfix settings."""
    if not isinstance(values, dict) or any(k not in values for k in PARAMETERS):
        raise PostfixConfigError("incomplete Postfix configuration snapshot")
    smtp = _milters(values["smtpd_milters"])
    local = _milters(values["non_smtpd_milters"])
    overrides = _overrides(master_overrides)
    protocol_raw = _value(values["milter_protocol"])
    default_action = _value(values["milter_default_action"]).lower()
    findings = []
    def flag(code):
        findings.append(code)
    if smtp.count(EXPECTED_MILTER) != 1:
        flag("smtp_milter_missing_or_duplicated")
    if len(smtp) != 1:
        flag("smtp_milter_chain_requires_review")
    if overrides:
        flag("master_service_milter_overrides_require_review")
    if not re.fullmatch(r"[0-9]{1,2}", protocol_raw) or not 2 <= int(protocol_raw) <= 6:
        flag("unsupported_milter_protocol")
        protocol = None
    else:
        protocol = int(protocol_raw)
    if default_action != "tempfail":
        flag("milter_failure_action_not_tempfail")
    return {
        "attempted": True,
        "ok": not findings,
        "status": "smtp_config_checked" if not findings else "requires_review",
        "smtpd_milter_attached": smtp.count(EXPECTED_MILTER) == 1,
        "non_smtpd_milter_attached": EXPECTED_MILTER in local,
        "scope": "postfix_configuration_only",
        "milter_protocol": protocol,
        "milter_default_action": default_action if default_action in
            ("tempfail", "accept", "reject", "quarantine") else "other",
        "service_override_keys": overrides,
        "findings": findings,
        "limitations": [
            "postconf main.cf values do not prove runtime reload or active master.cf service selection",
            "no SMTP transaction, Milter callback, hold, or mailbox disposition was exercised",
            "non_smtpd_milters is reported separately; local submission is not certified",
        ],
    }


def probe_postfix_config(executable=None):
    """Execute only bounded read-only postconf queries, fail closed on errors."""
    try:
        values = {key: _postconf(["-h", key], executable) for key in PARAMETERS}
        overrides = _postconf(["-P"], executable)
        return inspect_config(values, overrides)
    except PostfixConfigError as exc:
        return {"attempted": True, "ok": False, "status": "unverified",
                "error": str(exc), "findings": ["postfix_config_unverified"]}
