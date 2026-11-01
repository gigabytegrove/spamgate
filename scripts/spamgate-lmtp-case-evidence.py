#!/usr/bin/env python3
"""Disposable-CI-only exact-message Postfix -> Milter -> Dovecot LMTP evidence.

Read-only; never submits mail, changes MTA configuration, or reads message bodies.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys

from spamgate_bounded_command import CommandProbeError, capture_command

CONFIRM = 'DISPOSABLE-POSTFIX-LMTP-QUALIFICATION'
USER = 'spamgatebeta'
MAX_BYTES = 65536
UID = re.compile(r'[0-9a-fA-F]{32} [1-9][0-9]*\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
# The Go integration test exercises these identifiers on both the LDA and LMTP
# phases. Baseline UID sets distinguish previously delivered LDA copies.
CASES = {
    'legitimate': 'INBOX',
    'null-reverse-path': 'INBOX',
    'hold-request': 'INBOX',
    'tag-to-junk': 'Junk',
    'forged-verdict': 'INBOX',
    'synthetic-reject': None,
    'storage-failure': None,
}
BOXES = ('INBOX', 'Junk')


class EvidenceFailure(Exception):
    """Privacy-safe evidence failure."""


def require_disposable(confirm, env=None):
    env = os.environ if env is None else env
    if (confirm != CONFIRM or os.name != 'posix' or env.get('CI') != 'true' or
            env.get('GITHUB_ACTIONS') != 'true' or
            env.get('SPAMGATE_DISPOSABLE_POSTFIX_LMTP_LAB') != '1'):
        raise EvidenceFailure('explicit disposable CI confirmation required')


def query_uids(case, box, command=capture_command):
    if case not in CASES or box not in BOXES:
        raise EvidenceFailure('invalid case or mailbox identity')
    argv = ['/usr/bin/doveadm', 'search', '-u', USER, 'mailbox', box,
            'HEADER', 'Message-ID', '<' + case + '@example.org>']
    try:
        stdout, stderr, code = command(argv, timeout=5, max_bytes=16384)
    except (CommandProbeError, OSError) as exc:
        raise EvidenceFailure('bounded Dovecot identity query failed') from exc
    if code or stderr.strip():
        raise EvidenceFailure('Dovecot identity query failed')
    try:
        lines = stdout.decode('ascii', 'strict').splitlines()
    except UnicodeError as exc:
        raise EvidenceFailure('invalid Dovecot identity evidence') from exc
    if (len(lines) > 256 or any(not UID.fullmatch(line) for line in lines) or
            len(lines) != len(set(lines))):
        raise EvidenceFailure('ambiguous Dovecot identity evidence')
    return sorted(hashlib.sha256((box + '\0' + line).encode('ascii')).hexdigest()
                  for line in lines)


def snapshot(command=capture_command):
    return {'schema': 1, 'scope': 'disposable_postfix_lmtp_case_identities',
            'cases': {case: {box: query_uids(case, box, command)
                             for box in BOXES} for case in CASES}}


def validate(value):
    if (not isinstance(value, dict) or set(value) != {'schema', 'scope', 'cases'} or
            type(value['schema']) is not int or value['schema'] != 1 or
            value['scope'] != 'disposable_postfix_lmtp_case_identities' or
            not isinstance(value['cases'], dict) or set(value['cases']) != set(CASES)):
        raise EvidenceFailure('invalid case evidence schema')
    for case in CASES:
        boxes = value['cases'][case]
        if not isinstance(boxes, dict) or set(boxes) != set(BOXES):
            raise EvidenceFailure('invalid case mailbox inventory')
        for fingerprints in boxes.values():
            if (not isinstance(fingerprints, list) or len(fingerprints) > 256 or
                    any(not isinstance(v, str) or not DIGEST.fullmatch(v)
                        for v in fingerprints) or
                    len(fingerprints) != len(set(fingerprints))):
                raise EvidenceFailure('ambiguous case mailbox fingerprints')


def verify(before, after):
    validate(before)
    validate(after)
    accounted = set()
    for case, expected_box in CASES.items():
        for box in BOXES:
            previous = set(before['cases'][case][box])
            current = set(after['cases'][case][box])
            if not previous.issubset(current):
                raise EvidenceFailure('previously delivered case message disappeared')
            added = current - previous
            if len(added) != (1 if box == expected_box else 0):
                raise EvidenceFailure('case delivery count or disposition mismatch')
            if accounted.intersection(added):
                raise EvidenceFailure('duplicate identity across delivered cases')
            accounted.update(added)
    if len(accounted) != 5:
        raise EvidenceFailure('unexpected number of delivered identities')
    return {'schema': 1, 'ok': True,
            'type': 'disposable_postfix_lmtp_case_identity_evidence',
            'verified_cases': len(CASES), 'new_delivered_identities': len(accounted),
            'rejected_or_tempfailed_deliveries': 0,
            'scope': 'disposable_postfix_milter_dovecot_lmtp_only'}


def unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise EvidenceFailure('duplicate JSON evidence key')
        obj[key] = value
    return obj


def read_snapshot(path):
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise EvidenceFailure('unsafe evidence file')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise EvidenceFailure('oversized evidence file')
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              EvidenceFailure('non-finite JSON evidence value')))
    except (OSError, UnicodeError, ValueError) as exc:
        raise EvidenceFailure('invalid evidence file') from exc
    finally:
        if fd is not None:
            os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--snapshot', action='store_true')
    mode.add_argument('--verify', nargs=2, metavar=('BEFORE', 'AFTER'))
    parser.add_argument('--confirm', default='')
    args = parser.parse_args(argv)
    try:
        require_disposable(args.confirm)
        result = snapshot() if args.snapshot else verify(
            read_snapshot(args.verify[0]), read_snapshot(args.verify[1]))
    except EvidenceFailure as exc:
        result = {'schema': 1, 'ok': False, 'error': str(exc),
                  'type': 'disposable_postfix_lmtp_case_identity_evidence'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('ok', args.snapshot) and 'error' not in result else 1


if __name__ == '__main__':
    sys.exit(main())
