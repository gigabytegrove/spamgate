"""Bounded, opt-in, loopback Milter option-negotiation probe.

This module sends only SMFIC_OPTNEG (O). It never submits a message,
negotiates mail callbacks, or claims that a Postfix action was enforced.
"""

import socket
import struct

# Sendmail Milter v6: version, requested action capabilities, protocol flags.
MILTER_VERSION = 6
OFFERED_ACTIONS = 0x00000031  # ADDHDRS, CHGHDRS, QUARANTINE
OFFERED_PROTOCOL = 0  # Request all callbacks; do not suppress any stages.
NEGOTIATION_SIZE = 13  # One command byte and three network-order uint32s.


class MilterProtocolError(ValueError):
    """Invalid or incomplete Milter negotiation; never contains peer bytes."""


def _read_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        try:
            block = connection.recv(size - len(result))
        except (socket.timeout, TimeoutError) as exc:
            raise MilterProtocolError("milter negotiation response timed out") from exc
        except OSError as exc:
            raise MilterProtocolError("milter negotiation response read failed") from exc
        if not block:
            raise MilterProtocolError("milter negotiation response was truncated")
        result.extend(block)
    return bytes(result)


def verify_milter_protocol(connection):
    """Verify a bounded v2-v6 option reply on an already-connected socket.

    The caller owns the socket and closes it immediately after negotiation.
    This does not establish Milter callback, scanner, or mailbox behavior.
    """
    request = struct.pack("!I", NEGOTIATION_SIZE) + b"O" + struct.pack(
        "!III", MILTER_VERSION, OFFERED_ACTIONS, OFFERED_PROTOCOL
    )
    try:
        connection.sendall(request)
    except OSError as exc:
        raise MilterProtocolError("milter negotiation request write failed") from exc

    # Read the length first, before allocating a payload. A valid OPTNEG reply
    # is exactly 13 bytes. Refuse oversized, undersized and zero-length frames.
    length = struct.unpack("!I", _read_exact(connection, 4))[0]
    if length != NEGOTIATION_SIZE:
        raise MilterProtocolError("invalid milter negotiation frame length")
    response = _read_exact(connection, NEGOTIATION_SIZE)
    if response[0:1] != b"O":
        raise MilterProtocolError("unexpected milter negotiation response command")
    version, actions, protocol = struct.unpack("!III", response[1:])
    if not 2 <= version <= MILTER_VERSION:
        raise MilterProtocolError("unsupported milter negotiation version")
    if actions & ~OFFERED_ACTIONS:
        raise MilterProtocolError("milter advertised unoffered action capabilities")
    if protocol != 0:
        raise MilterProtocolError("milter advertised unrequested protocol shortcuts")
    return {"protocol_verified": True, "negotiated_version": version,
            "negotiated_actions": {
                "add_header": bool(actions & 0x01),
                "change_header": bool(actions & 0x10),
                "quarantine": bool(actions & 0x20),
            },
            "protocol_skip_flags": protocol}
