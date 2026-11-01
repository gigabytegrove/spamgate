"""Strict bounded JSON parsing for read-only SpamGate service diagnostics.

The HTTP health endpoint is not trusted merely because it accepts a loopback
connection. Do not allow duplicate keys or non-standard JSON values to turn
contradictory health data into a successful readiness report.
"""
import json

MAX_HEALTH_BYTES = 4096
ALLOWED_HEALTH_MIME = frozenset(("application/json", "application/health+json"))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate health JSON key: " + key[:80])
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("non-finite health JSON value: " + value)


def decode_health_response(raw, content_type):
    if len(raw) > MAX_HEALTH_BYTES:
        raise ValueError("health response exceeds 4096-byte limit")
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type not in ALLOWED_HEALTH_MIME:
        raise ValueError("health Content-Type must be application/json")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("health JSON is not valid UTF-8") from exc
    try:
        return json.loads(text, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except RecursionError as exc:
        raise ValueError("health JSON nesting exceeds parser limit") from exc
